package securitytest

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/url"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
	"github.com/stretchr/testify/require"
)

// stubProvider is a host-supplied identity provider whose exchange returns a
// fixed identity, so the browser flow runs without a network IdP.
type stubProvider struct {
	name     string
	trusted  bool
	identity authprovider.Identity
}

func (p *stubProvider) Name() string                  { return p.name }
func (p *stubProvider) DisplayName() string           { return p.name }
func (p *stubProvider) Issuer() string                { return "https://" + p.name + ".idp.security.test" }
func (p *stubProvider) PKCE() bool                    { return false }
func (p *stubProvider) ResponseModeFormPost() bool    { return false }
func (p *stubProvider) SupportsStepUp() bool          { return false }
func (p *stubProvider) TrustsEmailVerification() bool { return p.trusted }
func (p *stubProvider) Validate() error               { return nil }
func (p *stubProvider) AuthCodeURL(_ context.Context, req authprovider.AuthRequest) (string, error) {
	return p.Issuer() + "/authorize?" + url.Values{"state": {req.State}}.Encode(), nil
}
func (p *stubProvider) Exchange(context.Context, authprovider.ExchangeRequest) (authprovider.Identity, error) {
	return p.identity, nil
}

func withProviders(providers ...authprovider.Provider) hostOption {
	return withEngine(func(c *embedded.Config) { c.Identity.Providers = providers })
}

// providerCallback completes a browser provider login in one client.
func (h *host) providerCallback(name string) response {
	h.t.Helper()
	start := h.do(request{method: http.MethodGet, path: "//oidc/" + name + "/login"})
	require.Equal(h.t, http.StatusFound, start.status, start.String())
	loc, err := url.Parse(start.header.Get("Location"))
	require.NoError(h.t, err)
	q := url.Values{"state": {loc.Query().Get("state")}, "code": {"stub"}, "format": {"json"}}
	return h.do(request{method: http.MethodGet, path: "//oidc/" + name + "/callback?" + q.Encode(), cookies: start.cookies})
}

// session reads a token set from either the flat or the nested response shape.
func session(t *testing.T, r response) tokens {
	t.Helper()
	var flat struct {
		tokens
		TokenSet *tokens `json:"token_set"`
	}
	r.json(t, &flat)
	if flat.TokenSet != nil && flat.TokenSet.AccessToken != "" {
		return *flat.TokenSet
	}
	require.NotEmpty(t, flat.AccessToken, r.String())
	return flat.tokens
}

func (h *host) register(email string) tokens {
	h.t.Helper()
	resp := h.post("/register", map[string]string{"identifier": email, "username": unique("reg"), "password": password}, "")
	require.Less(h.t, resp.status, 300, resp.String())
	return session(h.t, resp)
}

func (h *host) verificationCode(email string) string {
	h.t.Helper()
	return h.mail.last(h.t, `^verification to=`+email+` code=(\S+)`)
}

func (h *host) userID(email string) string {
	h.t.Helper()
	u, err := h.client.GetUserByEmail(context.Background(), email)
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
	require.Equal(t, string(authkit.CodeVerificationRequired), env.Error.Code, r.String())
	require.Equal(t, "contact_unproven", env.Error.Metadata.Reason)
	return env.Error.Metadata.Identifier, env.Error.Metadata.Channel
}

// TestSecurityUnprovenContactCannotAddLoginMethods: whoever registers an
// address they never proved (possibly someone else's) cannot attach a login
// method that would outlive the real owner reclaiming it.
func TestSecurityUnprovenContactCannotAddLoginMethods(t *testing.T) {
	provider := &stubProvider{name: "linkidp", trusted: true}
	h := newHost(t, withHTTP(generousLimits), withProviders(provider), withEngine(func(c *embedded.Config) {
		c.Passkeys = embedded.PasskeyConfig{RPID: "localhost", RPDisplayName: "Security", Origins: []string{"http://localhost"}}
		c.SolanaNetwork = "devnet"
	}))
	email := unique("squat") + "@security.test"
	s := h.register(email)
	attempts := []struct {
		name string
		req  request
	}{
		{"link an identity provider", request{method: http.MethodPost, path: "/oidc/linkidp/link/start", body: map[string]any{}}},
		{"register a passkey", request{method: http.MethodPost, path: "/passkeys/register/begin", body: map[string]any{}}},
		{"enroll an authenticator app", request{method: http.MethodPost, path: "/user/2fa", body: map[string]string{"method": "totp"}}},
		{"link a Solana wallet", request{method: http.MethodPost, path: "/solana/link", body: map[string]any{}}},
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
	h := newHost(t, withHTTP(generousLimits), withEngine(func(c *embedded.Config) {
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
			{`INSERT INTO mfa_settings (user_id, enabled) VALUES ($1::uuid, true) ON CONFLICT (user_id) DO UPDATE SET enabled = true`, []any{userID}},
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
			token := h.mail.last(t, `^reset to=`+email+` .* token=(\S+)`)
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

// TestSecurityRegistrationNeverSelfVerifies: no registration policy marks an
// address verified without a proof of it.
func TestSecurityRegistrationNeverSelfVerifies(t *testing.T) {
	for _, policy := range []embedded.RegistrationVerificationPolicy{embedded.RegistrationVerificationNone, embedded.RegistrationVerificationOptional} {
		t.Run(string(policy), func(t *testing.T) {
			h := newHost(t, withHTTP(generousLimits), withEngine(func(c *embedded.Config) { c.Registration.Verification = policy }))
			email := unique("selfverify") + "@security.test"
			s := h.register(email)
			u, err := h.client.GetUserByEmail(context.Background(), email)
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
	untrusted := &stubProvider{name: "anyidp", identity: authprovider.Identity{Subject: unique("sub"), Email: victim, EmailVerified: true}}
	fresh := unique("provfresh") + "@security.test"
	trusted := &stubProvider{name: "trustedidp", trusted: true, identity: authprovider.Identity{Subject: unique("sub"), Email: victim, EmailVerified: true}}
	trustedFresh := &stubProvider{name: "trustedfresh", trusted: true, identity: authprovider.Identity{Subject: unique("sub"), Email: fresh, EmailVerified: true}}
	h := newHost(t, withHTTP(generousLimits), withProviders(untrusted, trusted, trustedFresh))
	ctx := context.Background()
	owner := h.newAccount("provowner")
	_, err := h.pool.Exec(ctx, `UPDATE users SET email = $1, email_verified = true WHERE id = $2::uuid`, victim, owner.id)
	require.NoError(t, err)

	resp := h.providerCallback("anyidp")
	require.Equal(t, http.StatusOK, resp.status, resp.String())
	var linkedTo string
	var email *string
	require.NoError(t, h.pool.QueryRow(ctx, `SELECT u.id::text, u.email::text FROM user_providers p JOIN users u ON u.id = p.user_id WHERE p.subject = $1`, untrusted.identity.Subject).Scan(&linkedTo, &email))
	require.NotEqual(t, owner.id, linkedTo, "an untrusted provider reached the owner's account")
	require.Nil(t, email, "an untrusted provider's address was stored")

	t.Run("control: trusted provider matches the existing address", func(t *testing.T) {
		resp := h.providerCallback("trustedidp")
		require.Equal(t, http.StatusConflict, resp.status, resp.String())
		require.Equal(t, string(authkit.CodeAccountExistsLinkRequired), resp.errorCode())
	})
	t.Run("control: trusted provider creates a verified account", func(t *testing.T) {
		resp := h.providerCallback("trustedfresh")
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		u, err := h.client.GetUserByEmail(ctx, fresh)
		require.NoError(t, err)
		require.True(t, u.EmailVerified)
	})
}
