package securitytest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/passkeytest"
	"github.com/open-rails/authkit/internal/testidp"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

// mfaSession signs a in with password and its email second factor and returns
// the session's access token.
func (h *host) mfaSession(a account) string {
	h.t.Helper()
	ch := h.passwordStep(a, "198.51.100.30")
	resp := h.secondStep(a, ch, h.mail.Last(h.t, iam.MessageLoginCode, a.email).Code, "198.51.100.30")
	require.Equal(h.t, http.StatusOK, resp.status, resp.String())
	return session(h.t, resp).AccessToken
}

// TestSecurityPasswordStepUpNeedsSecondFactor (N1): for an account with a
// second factor, a fresh authentication means that factor within the window. A
// stolen session plus the phished password never yields a token that
// regenerates backup codes, registers a passkey, adds or removes a factor,
// links or unlinks a provider or wallet, manages a sign-in key, changes or
// removes an address or deletes the account, on AuthKit's routes or a host's;
// each refusal says only the second factor clears it.
func TestSecurityPasswordStepUpNeedsSecondFactor(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withProviders(testidp.New(t).OAuth2("idp")), authtest.WithConfig(func(c *authkit.Config) {
		c.Passkeys = authkit.PasskeyConfig{RPID: "localhost", RPDisplayName: "Security", Origins: []string{"http://localhost"}}
		c.SolanaNetwork = iam.SolanaDevnet
	}))
	ctx := context.Background()
	victim := h.newAccount("stepup")
	h.enrollEmail2FA(victim)
	// The attacker's copy of the session is older than the fresh-auth window.
	stolen := authtest.StaleSession(t, h.auth, h.mfaSession(victim))
	_, claims := splitToken(t, stolen)
	sid, _ := claims["sid"].(string)
	require.NotEmpty(t, sid)

	// Every refusal says the account's second factor, not a password, clears it.
	requireMFAStepUp := func(resp response, msg string, args ...any) {
		t.Helper()
		require.Equal(t, http.StatusForbidden, resp.status, append([]any{msg + ": %s"}, append(args, resp)...)...)
		require.Equal(t, "step_up_required", resp.errorCode())
		var meta struct {
			Error struct {
				Metadata authflow.StepUpRequired `json:"metadata"`
			} `json:"error"`
		}
		resp.json(t, &meta)
		require.Equal(t, []string{"2fa"}, meta.Error.Metadata.StepUpMethods, "a password never clears the gate: %s", resp)
		require.Len(t, meta.Error.Metadata.Factors, 1, resp.String())
	}
	requireMFAStepUp(h.post("/me/step-up/password", map[string]string{"password": password}, stolen), "a password re-proved an account with a second factor")

	// What a password re-auth wrote before: the session is fresh, its second
	// factor is not. The token must still fail the MFA-if-enrolled gate.
	_, err := h.pool.Exec(ctx, `UPDATE profiles.refresh_sessions SET last_authenticated_at=now() WHERE id=$1::uuid`, sid)
	require.NoError(t, err)
	minted, err := h.auth.MintAccessToken(ctx, victim.id, iam.AccessTokenOptions{SessionID: sid})
	require.NoError(t, err)
	reproved := minted.Value
	_, claims = splitToken(t, reproved)
	require.Less(t, claims["auth_time"].(float64), float64(time.Now().Add(-15*time.Minute).Unix()), "auth_time follows the second factor")

	sensitive := verify.Sensitive(h.auth)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	hostRoute := func(token string) int {
		r := httptest.NewRequest(http.MethodPost, "https://host.security.test/payout-address", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		sensitive.ServeHTTP(w, r)
		return w.Code
	}
	someKey := uuid.NewString()
	attacks := []request{
		{method: http.MethodPost, path: "/me/2fa/backup-codes"},
		{method: http.MethodPost, path: "/me/passkeys/register/begin"},
		{method: http.MethodPost, path: "/me/2fa/setup", body: map[string]string{"method": "totp"}},
		{method: http.MethodPost, path: "/me/2fa/factors", body: map[string]string{"method": "totp", "code": "123456"}},
		{method: http.MethodDelete, path: "/me/2fa"},
		{method: http.MethodDelete, path: "/me/2fa/factors/" + someKey},
		{method: http.MethodPut, path: "/me/email", body: map[string]string{"email": unique("evil") + "@security.test"}},
		{method: http.MethodPut, path: "/me/phone", body: map[string]string{"phone_number": "+15550009999"}},
		{method: http.MethodDelete, path: "/me/phone"},
		{method: http.MethodPatch, path: "/me/sign-in-keys/" + someKey, body: map[string]string{"label": "evil"}},
		{method: http.MethodDelete, path: "/me/sign-in-keys/" + someKey},
		{method: http.MethodDelete, path: "/me/providers/idp"},
		{method: http.MethodDelete, path: "/me"},
		{method: http.MethodPut, path: "/me/password", body: map[string]string{"new_password": "Attacker-owned-passphrase-1"}},
		{method: http.MethodPost, path: "/oidc/idp/link/start", body: map[string]any{}},
		{method: http.MethodPut, path: "/me/solana-wallet", body: map[string]any{}},
	}
	for name, token := range map[string]string{"stolen": stolen, "password re-proved": reproved} {
		for _, req := range attacks {
			req.token = token
			requireMFAStepUp(h.do(req), "%s token %s %s", name, req.method, req.path)
		}
		require.Equal(t, http.StatusForbidden, hostRoute(token), "%s token on a host Sensitive route", name)
	}
	u, err := h.auth.User(ctx, iam.UserByID(victim.id))
	require.NoError(t, err)
	require.Equal(t, victim.email, *u.Email)

	t.Run("control: a second-factor step-up clears every gate", func(t *testing.T) {
		resp := h.post("/me/step-up/2fa/send", map[string]any{}, reproved)
		require.Equal(t, http.StatusAccepted, resp.status, resp.String())
		resp = h.post("/me/step-up/2fa", map[string]string{"code": h.mail.Last(t, iam.MessageLoginCode, victim.email).Code}, reproved)
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		fresh := session(t, resp).AccessToken
		require.Equal(t, http.StatusNoContent, hostRoute(fresh))
		resp = h.post("/me/2fa/backup-codes", nil, fresh)
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		resp = h.post("/oidc/idp/link/start", map[string]any{}, fresh)
		require.Equal(t, http.StatusOK, resp.status, resp.String())
	})
}

// TestSecurityEnrollmentTokenOutsideMiddleware (N7): a password-only
// enrollment token, issued before the second factor exists, reaches only
// AuthKit's enrollment routes. A host that authenticates out of band (Verify,
// then Allow) never gets a full identity from it.
func TestSecurityEnrollmentTokenOutsideMiddleware(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withAccountRoles))
	ctx := context.Background()
	holder := h.newAccount("enrolling")
	// An MFA-required role held without a factor (e.g. granted while 2FA was
	// off): signing in yields only an enrollment token.
	_, err := h.pool.Exec(ctx, `INSERT INTO profiles.group_user_roles(permission_group_id,user_id,role) VALUES($1::uuid,$2::uuid,'root:security')`, h.rootGroupID(), holder.id)
	require.NoError(t, err)
	resp := h.post("/password/login", map[string]string{"identifier": holder.email, "password": password}, "")
	login := authResult(t, resp)
	require.Equal(t, httpapi.AuthEnrollmentRequired, login.Status, resp.String())
	enrollment := login.Enrollment.TokenSet.AccessToken
	require.NotEmpty(t, enrollment)

	_, err = h.auth.Verify(ctx, enrollment)
	require.Error(t, err, "Verify accepted an enrollment-only token")
	// The token is genuine: the exempt enrollment route reads its claims.
	r := httptest.NewRequest(http.MethodPost, apiPrefix+"/me/2fa/setup", nil)
	r.Header.Set("Authorization", "Bearer "+enrollment)
	cl, err := h.auth.VerifyRequest(r)
	require.NoError(t, err)
	require.True(t, cl.TwoFAEnrollment)
	stored, _ := verify.IdentityFromContext(verify.SetClaims(ctx, cl))
	_, ok := iam.StateOf(stored)
	require.False(t, ok, "an enrollment token became an identity with authority")
	allowed, err := allow(ctx, h.auth, stored, ident.Perm("root:audit:read"), iam.RootGroup())
	require.NoError(t, err)
	require.False(t, allowed, "an enrollment token used the MFA-required role")

	t.Run("control: a full token of a role holder is allowed", func(t *testing.T) {
		admin := h.newAccount("fulltoken")
		h.grant(iam.RootGroup(), admin, "moderator")
		allowed, err := allow(ctx, h.auth, tokenIdentity(t, h.auth, h.login(admin).AccessToken), ident.RootUsersBan, iam.RootGroup())
		require.NoError(t, err)
		require.True(t, allowed)
	})
}

func withPasskeys(c *authkit.Config) {
	c.Passkeys = authkit.PasskeyConfig{RPID: "localhost", RPDisplayName: "Security", Origins: []string{"http://localhost"}}
}

// registerPasskey adds a software passkey to the account behind token.
func (h *host) registerPasskey(token string) *passkeytest.Authenticator {
	h.t.Helper()
	authn := passkeytest.New(h.t, "http://localhost")
	resp := h.post("/me/passkeys/register/begin", nil, token)
	require.Equal(h.t, http.StatusOK, resp.status, resp.String())
	var creation protocol.CredentialCreation
	resp.json(h.t, &creation)
	resp = h.post("/me/passkeys/register/finish", authn.Register(h.t, &creation), token)
	require.Equal(h.t, http.StatusCreated, resp.status, resp.String())
	return authn
}

// passkeyLogin signs in with authn; signCount must grow on every use.
func (h *host) passkeyLogin(authn *passkeytest.Authenticator, signCount uint32) response {
	h.t.Helper()
	resp := h.post("/passkeys/login/begin", map[string]any{}, "")
	require.Equal(h.t, http.StatusOK, resp.status, resp.String())
	var assertion protocol.CredentialAssertion
	resp.json(h.t, &assertion)
	return h.post("/passkeys/login/finish", authn.Assert(h.t, &assertion, signCount), "")
}

// TestSecurityPasswordStepUpOnPasskeySession (P5): a token claims MFA only as
// of its session's last MFA proof. A password step-up on a stolen passkey
// session of an account with no enrolled factor is fresh, but never acr=mfa.
func TestSecurityPasswordStepUpOnPasskeySession(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withPasskeys))
	victim := h.newAccount("p5victim")
	authn := h.registerPasskey(h.login(victim).AccessToken)
	resp := h.passkeyLogin(authn, 1)
	require.Equal(t, http.StatusOK, resp.status, resp.String())
	_, claims := splitToken(t, session(t, resp).AccessToken)
	require.Equal(t, iam.AssuranceLevelMFA, claims["acr"], "control: a passkey sign-in is MFA")
	// The attacker's copy of the session is older than the fresh-auth window.
	resp = h.post("/me/step-up/password", map[string]string{"password": password}, authtest.StaleSession(t, h.auth, session(t, resp).AccessToken))
	require.Equal(t, http.StatusOK, resp.status, resp.String())
	stepped := session(t, resp).AccessToken
	_, claims = splitToken(t, stepped)
	require.Equal(t, iam.AssuranceLevelPassword, claims["acr"], "a password re-auth made a passkey session MFA-fresh")
	require.NotContains(t, claims["amr"], "mfa")
	require.Nil(t, claims["mfa_enrolled"])

	route := verify.Sensitive(h.auth)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	r := httptest.NewRequest(http.MethodPost, "https://host.security.test/payout-address", nil)
	r.Header.Set("Authorization", "Bearer "+stepped)
	w := httptest.NewRecorder()
	route.ServeHTTP(w, r)
	require.Equal(t, http.StatusNoContent, w.Code, "a password is this account's step-up: %s", w.Body.String())
}

// TestSecurityPasskeyHolderNeedsPasskey (P7): a holder of an MFA-required role
// whose only strong credential is a passkey signs in with it. A password never
// yields an enrollment token that would let whoever typed it enroll a factor
// of their own.
func TestSecurityPasskeyHolderNeedsPasskey(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withAccountRoles), authtest.WithConfig(withPasskeys))
	ctx := context.Background()
	holder := h.newAccount("p7holder")
	authn := h.registerPasskey(h.login(holder).AccessToken)
	// The role came while 2FA was off, or was made MFA-required later.
	_, err := h.pool.Exec(ctx, `INSERT INTO profiles.group_user_roles(permission_group_id,user_id,role) VALUES($1::uuid,$2::uuid,'root:security')`, h.rootGroupID(), holder.id)
	require.NoError(t, err)
	resp := h.post("/password/login", map[string]string{"identifier": holder.email, "password": password}, "")
	require.Equal(t, http.StatusForbidden, resp.status, resp.String())
	require.Equal(t, "passkey_required", resp.errorCode(), "a password yielded something other than a passkey demand")
	require.NotContains(t, resp.String(), "access_token")

	t.Run("control: the passkey signs in with MFA", func(t *testing.T) {
		resp := h.passkeyLogin(authn, 1)
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		_, claims := splitToken(t, session(t, resp).AccessToken)
		require.Equal(t, iam.AssuranceLevelMFA, claims["acr"])
	})
}

// TestSecurityResetAccountMFA (R2): under Required 2FA an account whose only
// strong credential is a lost passkey answers passkey_required to every other
// sign-in. The system's ResetAccountMFA removes its passkeys, factors,
// backup codes, device keys and sessions and tells its address; the next
// password sign-in enrolls a factor. No other identity may reset an account.
func TestSecurityResetAccountMFA(t *testing.T) {
	optional := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withAccountRoles), authtest.WithConfig(withPasskeys), authtest.WithConfig(withDeviceKeys))
	ctx := context.Background()
	holder, lost, admin := optional.newAccount("r2holder"), optional.newAccount("r2lost"), optional.newAccount("r2admin")
	authn := optional.registerPasskey(optional.login(holder).AccessToken)
	laptop := newDeviceKey(t)
	require.Equal(t, http.StatusOK, optional.deviceEnroll(laptop, holder.email, nil).status)
	optional.enrollEmail2FA(lost)
	optional.grant(iam.RootGroup(), admin, "siteadmin")
	// The deployment then requires 2FA.
	h := optional.replica(authtest.WithConfig(func(c *authkit.Config) { c.TwoFactor.Mode = iam.TwoFactorRequired }))

	signIn := func(a account) response {
		return h.post("/password/login", map[string]string{"identifier": a.email, "password": password}, "")
	}
	resp := signIn(holder)
	require.Equal(t, http.StatusForbidden, resp.status, resp.String())
	require.Equal(t, "passkey_required", resp.errorCode())
	resp = h.passkeyLogin(authn, 1)
	require.Equal(t, http.StatusOK, resp.status, resp.String())
	passkeySession := session(t, resp)

	require.NoError(t, h.auth.ResetAccountMFA(ctx, holder.id))
	require.Len(t, h.mail.Messages(iam.MessageMFAReset, holder.email), 1)
	require.Equal(t, http.StatusUnauthorized, h.refresh(passkeySession.RefreshToken).status, "a session outlived the reset")
	require.NotEqual(t, http.StatusOK, h.passkeyLogin(authn, 2).status, "the passkey outlived the reset")
	keys, err := h.auth.DeviceKeys(ctx, holder.id)
	require.NoError(t, err)
	for _, key := range keys {
		require.NotNil(t, key.RevokedAt, "a device key outlived the reset")
	}

	resp = signIn(holder)
	login := authResult(t, resp)
	require.Equal(t, httpapi.AuthEnrollmentRequired, login.Status, resp.String())
	_, resp = h.enrollTOTP(login.Enrollment.TokenSet.AccessToken)
	_, claims := splitToken(t, session(t, resp).AccessToken)
	require.Equal(t, iam.AssuranceLevelMFA, claims["acr"], "control: the enrolled factor signs in")

	t.Run("factors and backup codes go too", func(t *testing.T) {
		require.NoError(t, h.auth.ResetAccountMFA(ctx, lost.id))
		var factors, settings int
		require.NoError(t, h.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM profiles.mfa_factors WHERE user_id=$1::uuid), (SELECT count(*) FROM profiles.mfa_settings WHERE user_id=$1::uuid)`, lost.id).Scan(&factors, &settings))
		require.Zero(t, factors)
		require.Zero(t, settings)
		require.Equal(t, httpapi.AuthEnrollmentRequired, authResult(t, signIn(lost)).Status)
	})
}
