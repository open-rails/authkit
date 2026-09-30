package securitytest

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/testidp"
	"github.com/open-rails/authkit/provider"
	"github.com/stretchr/testify/require"
)

func withProviders(providers ...provider.Provider) authtest.Option {
	return authtest.WithDeps(func(d *authkit.Deps) { d.Providers = providers })
}

// providerCallback signs id in at idp through the browser flow of provider
// name, in one client, and returns the callback's JSON answer.
func (h *host) providerCallback(idp *testidp.IdP, name string, id testidp.Identity) response {
	h.t.Helper()
	start := h.do(request{method: http.MethodGet, path: "//oidc/" + name + "/login"})
	require.Equal(h.t, http.StatusFound, start.status, start.String())
	q := idp.Redirect(h.t, start.header.Get("Location"), id)
	q.Set("format", "json")
	return h.do(request{method: http.MethodGet, path: "//oidc/" + name + "/callback?" + q.Encode(), cookies: start.cookies})
}

// session is a complete sign-in's tokens: an AuthResult's, or the one a
// factor's creation carries (TwoFactorFactorCreated.auth).
func session(t *testing.T, r response) tokens {
	t.Helper()
	require.Less(t, r.status, 300, r.String())
	var body struct {
		httpapi.AuthResult
		Auth *httpapi.AuthResult `json:"auth"`
	}
	r.json(t, &body)
	res := body.AuthResult
	if res.Status == "" && body.Auth != nil {
		res = *body.Auth
	}
	require.Equal(t, httpapi.AuthComplete, res.Status, r.String())
	require.NotNil(t, res.TokenSet, r.String())
	out := tokens{AccessToken: res.TokenSet.AccessToken}
	if res.TokenSet.RefreshToken != nil {
		out.RefreshToken = *res.TokenSet.RefreshToken
	}
	require.NotEmpty(t, out.AccessToken, r.String())
	return out
}

func (h *host) register(email string) tokens {
	h.t.Helper()
	resp := h.post("/register", map[string]string{"identifier": email, "username": unique("reg"), "password": password}, "")
	require.Less(h.t, resp.status, 300, resp.String())
	return session(h.t, resp)
}

func (h *host) verificationCode(email string) string {
	h.t.Helper()
	return h.mail.Last(h.t, iam.MessageVerification, email).Code
}

func (h *host) userID(email string) string {
	h.t.Helper()
	u, err := h.auth.User(context.Background(), iam.UserByEmail(email))
	require.NoError(h.t, err)
	return u.ID
}

func contactOf(t *testing.T, r response) (string, string) {
	t.Helper()
	var env struct {
		Error struct {
			Code     string `json:"code"`
			Metadata struct {
				Identifier string `json:"identifier"`
				Channel    string `json:"channel"`
				Reason     string `json:"reason"`
			} `json:"metadata"`
		} `json:"error"`
	}
	r.json(t, &env)
	require.Equal(t, string(errmodel.CodeVerificationRequired), env.Error.Code, r.String())
	require.Equal(t, "contact_unproven", env.Error.Metadata.Reason)
	return env.Error.Metadata.Identifier, env.Error.Metadata.Channel
}

// TestSecurityUnprovenContactCannotAddLoginMethods: whoever registers an
// address they never proved (possibly someone else's) cannot attach a login
// method that would outlive the real owner reclaiming it.
func TestSecurityUnprovenContactCannotAddLoginMethods(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withProviders(testidp.New(t).OAuth2("linkidp")), authtest.WithConfig(func(c *authkit.Config) {
		c.Passkeys = authkit.PasskeyConfig{RPID: "localhost", RPDisplayName: "Security", Origins: []string{"http://localhost"}}
		c.SolanaNetwork = "devnet"
	}))
	email := unique("squat") + "@security.test"
	s := h.register(email)
	attempts := []struct {
		name string
		req  request
	}{
		{"link an identity provider", request{method: http.MethodPost, path: "/oidc/linkidp/link/start", body: map[string]any{}}},
		{"register a passkey", request{method: http.MethodPost, path: "/me/passkeys/register/begin"}},
		{"enroll an authenticator app", request{method: http.MethodPost, path: "/me/2fa/setup", body: map[string]string{"method": "totp"}}},
		{"link a Solana wallet", request{method: http.MethodPut, path: "/me/solana-wallet", body: map[string]any{}}},
	}
	for _, a := range attempts {
		t.Run(a.name, func(t *testing.T) {
			a.req.token = s.AccessToken
			resp := h.do(a.req)
			require.Equal(t, http.StatusForbidden, resp.status, resp.String())
			identifier, channel := contactOf(t, resp)
			require.Equal(t, email, identifier)
			require.Equal(t, "email", channel)
		})
	}
	t.Run("control: after proving the address", func(t *testing.T) {
		resp := h.post("/verify/request", map[string]string{"identifier": email}, "")
		require.Less(t, resp.status, 300, resp.String())
		resp = h.post("/verify/confirm", map[string]string{"identifier": email, "code": h.verificationCode(email)}, s.AccessToken)
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		for _, a := range attempts[:3] {
			a.req.token = s.AccessToken
			resp := h.do(a.req)
			require.Less(t, resp.status, 300, "%s: %s", a.name, resp)
		}
	})
}

// TestSecurityPreRegistrationTakeover: an attacker registers the victim's
// address and plants credentials (as a pre-#393 deployment or a host import
// could have). The first proof of the address by its real owner must leave
// the attacker nothing: no session, password, provider, device key or factor.
func TestSecurityPreRegistrationTakeover(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(func(c *authkit.Config) {
		c.Registration.PasswordlessLogin = true
	}))
	ctx := context.Background()
	plant := func(t *testing.T, userID string) {
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		for _, stmt := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO user_providers (user_id, issuer, provider_slug, subject) VALUES ($1::uuid, 'https://github.com/login/oauth', 'github', $2)`, []any{userID, unique("attacker")}},
			{`INSERT INTO user_device_keys (user_id, public_key) VALUES ($1::uuid, $2)`, []any{userID, key}},
			{`INSERT INTO mfa_factors (user_id, method, totp_secret, is_default) VALUES ($1::uuid, 'totp', $2, true)`, []any{userID, key}},
			{`INSERT INTO mfa_settings (user_id) VALUES ($1::uuid) ON CONFLICT (user_id) DO NOTHING`, []any{userID}},
		} {
			_, err := h.pool.Exec(ctx, stmt.sql, stmt.args...)
			require.NoError(t, err)
		}
	}
	requireRetired := func(t *testing.T, userID string) {
		var providers, keys, factors int
		var verified bool
		require.NoError(t, h.pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM user_providers WHERE user_id = $1::uuid),
			(SELECT count(*) FROM user_device_keys WHERE user_id = $1::uuid AND revoked_at IS NULL),
			(SELECT count(*) FROM mfa_factors WHERE user_id = $1::uuid),
			(SELECT email_verified FROM users WHERE id = $1::uuid)`, userID).
			Scan(&providers, &keys, &factors, &verified))
		require.Zero(t, providers, "attacker's provider link survived")
		require.Zero(t, keys, "attacker's device key survived")
		require.Zero(t, factors, "attacker's second factor survived")
		require.True(t, verified)
	}
	for _, tc := range []struct {
		name  string
		prove func(t *testing.T, email string) tokens
	}{
		{"owner resets the password", func(t *testing.T, email string) tokens {
			require.Less(t, h.post("/password/reset/request", map[string]string{"identifier": email}, "").status, 300)
			token := h.mail.Last(t, iam.MessagePasswordReset, email).Token
			resp := h.post("/password/reset/confirm", map[string]string{"token": token, "new_password": "Owner-reclaimed-passphrase-4"}, "")
			require.Less(t, resp.status, 300, resp.String())
			resp = h.post("/password/login", map[string]string{"identifier": email, "password": "Owner-reclaimed-passphrase-4"}, "")
			require.Equal(t, http.StatusOK, resp.status, resp.String())
			return session(t, resp)
		}},
		{"owner signs in with an email code", func(t *testing.T, email string) tokens {
			require.Less(t, h.post("/passwordless/start", map[string]string{"identifier": email, "mode": "code"}, "").status, 300)
			resp := h.post("/passwordless/confirm", map[string]string{"identifier": email, "code": h.verificationCode(email)}, "")
			require.Equal(t, http.StatusOK, resp.status, resp.String())
			return session(t, resp)
		}},
		{"owner confirms the verification code on another device", func(t *testing.T, email string) tokens {
			require.Less(t, h.post("/verify/request", map[string]string{"identifier": email}, "").status, 300)
			resp := h.post("/verify/confirm", map[string]string{"identifier": email, "code": h.verificationCode(email)}, "")
			require.Equal(t, http.StatusOK, resp.status, resp.String())
			return session(t, resp)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			email := unique("victim") + "@security.test"
			attacker := h.register(email)
			attackerLogin := h.post("/password/login", map[string]string{"identifier": email, "password": password}, "")
			require.Equal(t, http.StatusOK, attackerLogin.status, attackerLogin.String())
			second := session(t, attackerLogin)
			userID := h.userID(email)
			plant(t, userID)

			owner := tc.prove(t, email)
			require.Equal(t, http.StatusOK, h.get("/me", owner.AccessToken).status)
			requireRetired(t, userID)
			for _, s := range []tokens{attacker, second} {
				require.Equal(t, http.StatusUnauthorized, h.refresh(s.RefreshToken).status, "an attacker session survived")
			}
			login := h.post("/password/login", map[string]string{"identifier": email, "password": password}, "")
			require.Equal(t, http.StatusUnauthorized, login.status, "the attacker's password survived: %s", login)
			require.Equal(t, http.StatusOK, h.refresh(owner.RefreshToken).status)
		})
	}
	t.Run("control: the registrant verifies from their own session", func(t *testing.T) {
		email := unique("honest") + "@security.test"
		own := h.register(email)
		require.Less(t, h.post("/verify/request", map[string]string{"identifier": email}, "").status, 300)
		resp := h.post("/verify/confirm", map[string]string{"identifier": email, "code": h.verificationCode(email)}, own.AccessToken)
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		require.Equal(t, http.StatusOK, h.refresh(own.RefreshToken).status, "the proving session was revoked")
		login := h.post("/password/login", map[string]string{"identifier": email, "password": password}, "")
		require.Equal(t, http.StatusOK, login.status, "the registrant's password was dropped: %s", login)
	})
}

// TestSecurityPreRegistrationContactChange (ak#417): a squatter who
// registered the victim's address cannot make the account proven by proving
// an address of its own through a contact change. The real owner's first
// proof still leaves the squatter nothing, not even a recovery channel.
func TestSecurityPreRegistrationContactChange(t *testing.T) {
	h := newHost(t, withSMS, withHTTP(generousLimits))
	ctx := context.Background()
	victim := unique("ccvictim") + "@security.test"
	attackerPhone := "+1555" + uniqueDigits(7)
	squatter := h.register(victim)
	userID := h.userID(victim)

	resp := h.do(request{method: http.MethodPut, path: "/me/phone", body: map[string]string{"phone_number": attackerPhone}, token: squatter.AccessToken})
	require.Equal(t, http.StatusForbidden, resp.status, "an unproven account started proving a second address: %s", resp)
	identifier, channel := contactOf(t, resp)
	require.Equal(t, victim, identifier)
	require.Equal(t, "email", channel)
	require.Empty(t, h.mail.Messages(iam.MessageVerification, attackerPhone), "a code went to the squatter's phone")
	require.Equal(t, "verification_required", h.post("/me/2fa/setup", map[string]string{"method": "totp"}, squatter.AccessToken).errorCode())

	require.Less(t, h.post("/password/reset/request", map[string]string{"identifier": victim}, "").status, 300)
	token := h.mail.Last(t, iam.MessagePasswordReset, victim).Token
	resp = h.post("/password/reset/confirm", map[string]string{"token": token, "new_password": "Victim-owns-this-now-7"}, "")
	require.Less(t, resp.status, 300, resp.String())
	u, err := h.auth.User(ctx, iam.UserByID(userID))
	require.NoError(t, err)
	require.True(t, u.EmailVerified)
	require.Nil(t, u.Phone, "the squatter kept a recovery channel")
	require.Equal(t, http.StatusUnauthorized, h.refresh(squatter.RefreshToken).status, "the squatter's session survived")
	login := h.post("/password/login", map[string]string{"identifier": victim, "password": password}, "")
	require.Equal(t, http.StatusUnauthorized, login.status, "the squatter's password survived: %s", login)

	t.Run("a change requested before the account lost its proof dies with it", func(t *testing.T) {
		a := h.newAccount("ccproven")
		access := h.login(a).AccessToken
		phone := "+1555" + uniqueDigits(7)
		resp := h.do(request{method: http.MethodPut, path: "/me/phone", body: map[string]string{"phone_number": phone}, token: access})
		require.Equal(t, http.StatusAccepted, resp.status, resp.String())
		unproven := unique("ccunproven") + "@security.test"
		_, err := h.auth.UpdateUser(ctx, iam.SystemActor(), a.id, iam.UserUpdate{Email: &unproven})
		require.NoError(t, err)
		resp = h.post("/verify/confirm", map[string]string{"identifier": phone, "code": h.mail.Last(t, iam.MessageVerification, phone).Code}, access)
		require.Equal(t, "invalid_code", resp.errorCode(), resp.String())
		u, err := h.auth.User(ctx, iam.UserByID(a.id))
		require.NoError(t, err)
		require.Nil(t, u.Phone)
	})

	t.Run("control: an unproven account may replace its address", func(t *testing.T) {
		typo := unique("cctypo") + "@security.test"
		own := h.register(typo)
		fixed := unique("ccfixed") + "@security.test"
		resp := h.do(request{method: http.MethodPut, path: "/me/email", body: map[string]string{"email": fixed}, token: own.AccessToken})
		require.Equal(t, http.StatusAccepted, resp.status, resp.String())
		resp = h.post("/verify/confirm", map[string]string{"identifier": fixed, "code": h.verificationCode(fixed)}, own.AccessToken)
		require.Equal(t, http.StatusNoContent, resp.status, resp.String())
		u, err := h.auth.User(ctx, iam.UserByEmail(fixed))
		require.NoError(t, err)
		require.True(t, u.EmailVerified)
		require.Equal(t, http.StatusOK, h.refresh(own.RefreshToken).status, "the proving session was revoked")
		h.register(typo) // the replaced address is free again
	})
}

// TestSecurityRegistrationNeverSelfVerifies: no registration policy marks an
// address verified without a proof of it.
func TestSecurityRegistrationNeverSelfVerifies(t *testing.T) {
	for _, policy := range []iam.RegistrationVerificationPolicy{iam.RegistrationVerificationNone, iam.RegistrationVerificationOptional} {
		t.Run(string(policy), func(t *testing.T) {
			h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(func(c *authkit.Config) { c.Registration.Verification = policy }))
			email := unique("selfverify") + "@security.test"
			s := h.register(email)
			u, err := h.auth.User(context.Background(), iam.UserByEmail(email))
			require.NoError(t, err)
			require.False(t, u.EmailVerified)
			_, claims := splitToken(t, s.AccessToken)
			require.NotEqual(t, true, claims["email_verified"])
		})
	}
}

// TestSecurityProviderEmailTrust: an identity provider's email_verified claim
// makes an address verified, or matches an existing account, only when the
// provider is trusted to verify addresses.
func TestSecurityProviderEmailTrust(t *testing.T) {
	victim := unique("provvictim") + "@security.test"
	fresh := unique("provfresh") + "@security.test"
	untrusted, trusted, trustedFresh := testidp.New(t), testidp.New(t), testidp.New(t)
	h := newHost(t, withHTTP(generousLimits), withProviders(untrusted.OAuth2("anyidp", provider.WithTrustedEmailVerification(false)),
		trusted.OAuth2("trustedidp"), trustedFresh.OAuth2("trustedfresh")))
	ctx := context.Background()
	owner := h.newAccount("provowner")
	_, err := h.pool.Exec(ctx, `UPDATE users SET email = $1, email_verified = true WHERE id = $2::uuid`, victim, owner.id)
	require.NoError(t, err)

	claimed := testidp.Identity{Subject: unique("sub"), Email: victim, EmailVerified: true}
	resp := h.providerCallback(untrusted, "anyidp", claimed)
	require.Equal(t, http.StatusOK, resp.status, resp.String())
	var linkedTo string
	var email *string
	require.NoError(t, h.pool.QueryRow(ctx, `SELECT u.id::text, u.email::text FROM user_providers p JOIN users u ON u.id = p.user_id WHERE p.subject = $1`, claimed.Subject).Scan(&linkedTo, &email))
	require.NotEqual(t, owner.id, linkedTo, "an untrusted provider reached the owner's account")
	require.Nil(t, email, "an untrusted provider's address was stored")

	t.Run("control: trusted provider matches the existing address", func(t *testing.T) {
		resp := h.providerCallback(trusted, "trustedidp", testidp.Identity{Subject: unique("sub"), Email: victim, EmailVerified: true})
		require.Equal(t, http.StatusConflict, resp.status, resp.String())
		require.Equal(t, string(errmodel.CodeAccountExistsLinkRequired), resp.errorCode())
	})
	t.Run("control: trusted provider creates a verified account", func(t *testing.T) {
		resp := h.providerCallback(trustedFresh, "trustedfresh", testidp.Identity{Subject: unique("sub"), Email: fresh, EmailVerified: true})
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		u, err := h.auth.User(ctx, iam.UserByEmail(fresh))
		require.NoError(t, err)
		require.True(t, u.EmailVerified)
	})
}

// TestSecurityMemberEmailIsAnInvitation (N9): inviting a member by email
// never reveals whether an account holds the address, and never adds the
// account without its consent: every address gets the same 202, and only the
// emailed code, which only the account that proved the address accepts,
// whatever the address's case; a deleted account gets nothing. A failed
// verification link says nothing about the address either.
func TestSecurityMemberEmailIsAnInvitation(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC))
	ctx := context.Background()
	owner := h.newAccount("n9owner")
	group, base := h.newOrg(owner)
	ownerToken := h.login(owner).AccessToken
	verified := h.newAccount("n9verified")
	unverified := unique("n9unverified") + "@security.test"
	h.register(unverified)
	nobody := unique("n9nobody") + "@security.test"

	var answers []string
	for _, email := range []string{verified.email, unverified, nobody} {
		resp := h.post(base+"/invitations", map[string]string{"email": email, "role": "org:member"}, ownerToken)
		require.Equal(t, http.StatusAccepted, resp.status, resp.String())
		answers = append(answers, fmt.Sprintf("%d %q", resp.status, resp.body))
	}
	require.Equal(t, answers[0], answers[1])
	require.Equal(t, answers[0], answers[2])
	code := h.inviteCode(verified.email)
	roleOf := func(id string) iam.Role {
		roles, err := h.auth.GroupRoles(ctx, group, []iam.Subject{iam.UserSubject(id)})
		require.NoError(t, err)
		return roles[iam.UserSubject(id)]
	}
	require.Empty(t, roleOf(verified.id), "a verified address was added without consent")

	stranger := h.newAccount("n9stranger")
	resp := h.post("/invitations/redeem", map[string]string{"code": code}, h.login(stranger).AccessToken)
	require.Equal(t, http.StatusNotFound, resp.status, "another account accepted the invitation: %s", resp)
	require.Empty(t, roleOf(stranger.id))
	resp = h.post("/invitations/redeem", map[string]string{"code": code}, h.login(verified).AccessToken)
	require.Equal(t, http.StatusOK, resp.status, resp.String())
	require.Equal(t, h.role(orgPersona, "member"), roleOf(verified.id), "control: the invited account accepts")

	t.Run("an upper-cased address invites only its proven owner", func(t *testing.T) {
		proven := h.newAccount("n9upper")
		resp := h.post(base+"/invitations", map[string]string{"email": strings.ToUpper(proven.email), "role": "org:member"}, ownerToken)
		require.Equal(t, http.StatusAccepted, resp.status, resp.String())
		require.Empty(t, roleOf(proven.id), "a verified address is invited, never added")
		code := h.inviteCode(proven.email)
		resp = h.post("/invitations/redeem", map[string]string{"code": code}, h.login(stranger).AccessToken)
		require.Equal(t, http.StatusNotFound, resp.status, "another account accepted the invitation: %s", resp)
		resp = h.post("/invitations/redeem", map[string]string{"code": code}, h.login(proven).AccessToken)
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		require.Equal(t, h.role(orgPersona, "member"), roleOf(proven.id))
	})
	t.Run("a deleted account's address gets no role", func(t *testing.T) {
		gone := h.newAccount("n9gone")
		require.NoError(t, opErr(h.auth.DeleteUsers(ctx, iam.SystemActor(), []string{gone.id})))
		resp := h.post(base+"/invitations", map[string]string{"email": gone.email, "role": "org:member"}, ownerToken)
		require.Equal(t, http.StatusAccepted, resp.status, resp.String())
		require.Empty(t, roleOf(gone.id), "a deleted account received a role")
	})

	t.Run("a failed verification link is one answer", func(t *testing.T) {
		var answers []string
		for _, email := range []string{verified.email, unverified, nobody} {
			resp := h.post("/verify/confirm", map[string]string{"identifier": email, "token": unique("bogus-link-token-000000000000000")}, "")
			answers = append(answers, fmt.Sprintf("%d %s", resp.status, resp.errorCode()))
		}
		require.Equal(t, []string{"400 invalid_link", "400 invalid_link", "400 invalid_link"}, answers)
	})
}
