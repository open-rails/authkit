package securitytest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/passkeytest"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

// mfaSession signs a in with password and its email second factor and returns
// the session id.
func (h *host) mfaSession(a account) string {
	h.t.Helper()
	ch := h.passwordStep(a, "198.51.100.30")
	resp := h.secondStep(a, ch, h.mail.Last(h.t, authtest.LoginCode, a.email).Code, "198.51.100.30")
	require.Equal(h.t, http.StatusOK, resp.status, resp.String())
	_, claims := splitToken(h.t, session(h.t, resp).AccessToken)
	sid, _ := claims["sid"].(string)
	require.NotEmpty(h.t, sid)
	return sid
}

// sessionToken mints a fresh access token for an existing session.
func (h *host) sessionToken(userID, sid string) string {
	h.t.Helper()
	tok, err := h.auth.MintAccessToken(context.Background(), userID, iam.AccessTokenOptions{SessionID: sid})
	require.NoError(h.t, err)
	return tok.Value
}

// TestSecurityPasswordStepUpNeedsSecondFactor (N1): for an account with a
// second factor, a fresh authentication means that factor within the window. A
// stolen session plus the phished password never yields a token that
// regenerates backup codes, registers a passkey, adds a factor, links a
// provider or changes the address, on AuthKit's routes or a host's.
func TestSecurityPasswordStepUpNeedsSecondFactor(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withProviders(&stubProvider{name: "stub"}), withEngine(func(c *authkit.Config) {
		c.Passkeys = authkit.PasskeyConfig{RPID: "localhost", RPDisplayName: "Security", Origins: []string{"http://localhost"}}
	}))
	ctx := context.Background()
	victim := h.newAccount("stepup")
	h.enrollEmail2FA(victim)
	sid := h.mfaSession(victim)
	// The attacker's copy of the session is older than the fresh-auth window.
	_, err := h.pool.Exec(ctx, `UPDATE profiles.refresh_sessions SET last_authenticated_at=now()-interval '20 minutes', mfa_authenticated_at=now()-interval '20 minutes' WHERE id=$1::uuid`, sid)
	require.NoError(t, err)
	stolen := h.sessionToken(victim.id, sid)

	resp := h.post("/step-up/password", map[string]string{"password": password}, stolen)
	require.Equal(t, http.StatusForbidden, resp.status, "a password re-proved an account with a second factor: %s", resp)
	require.Equal(t, "step_up_required", resp.errorCode())
	var meta struct {
		Error struct {
			Metadata struct {
				MFARequired bool `json:"mfa_required"`
			} `json:"metadata"`
		} `json:"error"`
	}
	resp.json(t, &meta)
	require.True(t, meta.Error.Metadata.MFARequired)

	// What a password re-auth wrote before: the session is fresh, its second
	// factor is not. The token must still fail the MFA-if-enrolled gate.
	_, err = h.pool.Exec(ctx, `UPDATE profiles.refresh_sessions SET last_authenticated_at=now() WHERE id=$1::uuid`, sid)
	require.NoError(t, err)
	reproved := h.sessionToken(victim.id, sid)
	_, claims := splitToken(t, reproved)
	require.Less(t, claims["auth_time"].(float64), float64(time.Now().Add(-15*time.Minute).Unix()), "auth_time follows the second factor")

	sensitive := h.auth.Require(verify.Sensitive()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })))
	hostRoute := func(token string) int {
		r := httptest.NewRequest(http.MethodPost, "https://host.security.test/payout-address", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		sensitive.ServeHTTP(w, r)
		return w.Code
	}
	attacks := []request{
		{method: http.MethodPost, path: "/user/2fa/backup-codes", body: map[string]any{}},
		{method: http.MethodPost, path: "/passkeys/register/begin", body: map[string]any{}},
		{method: http.MethodPost, path: "/user/2fa", body: map[string]string{"method": "totp"}},
		{method: http.MethodDelete, path: "/user/2fa", body: map[string]any{}},
		{method: http.MethodPost, path: "/verify/request", body: map[string]string{"identifier": unique("evil") + "@security.test"}},
		{method: http.MethodPost, path: "/oidc/stub/link/start", body: map[string]any{}},
	}
	for name, token := range map[string]string{"stolen": stolen, "password re-proved": reproved} {
		for _, req := range attacks {
			req.token = token
			resp := h.do(req)
			require.Equal(t, http.StatusForbidden, resp.status, "%s token %s %s: %s", name, req.method, req.path, resp)
			require.Equal(t, "step_up_required", resp.errorCode())
		}
		require.Equal(t, http.StatusForbidden, hostRoute(token), "%s token on a host Sensitive route", name)
	}
	u, err := h.auth.User(ctx, iam.UserByID(victim.id))
	require.NoError(t, err)
	require.Equal(t, victim.email, u.Email)

	t.Run("control: a second-factor step-up clears every gate", func(t *testing.T) {
		resp := h.post("/step-up/2fa", map[string]any{}, reproved)
		require.Equal(t, http.StatusForbidden, resp.status, resp.String())
		require.Equal(t, "2fa_required", resp.errorCode())
		resp = h.post("/step-up/2fa", map[string]string{"code": h.mail.Last(t, authtest.LoginCode, victim.email).Code}, reproved)
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		fresh := session(t, resp).AccessToken
		require.Equal(t, http.StatusNoContent, hostRoute(fresh))
		resp = h.post("/user/2fa/backup-codes", map[string]any{}, fresh)
		require.Equal(t, http.StatusOK, resp.status, resp.String())
	})
}

// TestSecurityEnrollmentTokenOutsideMiddleware (N7): a password-only
// enrollment token, issued before the second factor exists, reaches only
// AuthKit's enrollment routes. A host that authenticates out of band (Verify,
// then Allow) never gets a full actor from it.
func TestSecurityEnrollmentTokenOutsideMiddleware(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withAccountRoles))
	ctx := context.Background()
	holder := h.newAccount("enrolling")
	// An MFA-required role held without a factor (e.g. granted while 2FA was
	// off): signing in yields only an enrollment token.
	_, err := h.pool.Exec(ctx, `INSERT INTO profiles.group_user_roles(permission_group_id,user_id,role) VALUES($1::uuid,$2::uuid,'security')`, h.rootGroupID(), holder.id)
	require.NoError(t, err)
	resp := h.post("/password/login", map[string]string{"identifier": holder.email, "password": password}, "")
	require.Equal(t, http.StatusForbidden, resp.status, resp.String())
	require.Equal(t, "2fa_enrollment_required", resp.errorCode())
	var body struct {
		Error struct {
			Metadata struct {
				TokenSet tokens `json:"token_set"`
			} `json:"metadata"`
		} `json:"error"`
	}
	resp.json(t, &body)
	enrollment := body.Error.Metadata.TokenSet.AccessToken
	require.NotEmpty(t, enrollment)

	_, err = h.auth.Verifier().Verify(ctx, enrollment)
	require.Error(t, err, "Verify accepted an enrollment-only token")
	// The token is genuine: the exempt enrollment route reads its claims.
	r := httptest.NewRequest(http.MethodGet, apiPrefix+"/user/2fa", nil)
	r.Header.Set("Authorization", "Bearer "+enrollment)
	cl, err := h.auth.Verifier().VerifyRequest(r)
	require.NoError(t, err)
	require.True(t, cl.TwoFAEnrollment)
	_, ok := verify.ActorFromClaims(cl)
	require.False(t, ok, "an enrollment token became an actor")
	allowed, err := verify.Allow(ctx, h.auth, cl, ident.Perm("root:audit:read"), iam.RootGroup())
	require.NoError(t, err)
	require.False(t, allowed, "an enrollment token used the MFA-required role")

	t.Run("control: a full token of a role holder is allowed", func(t *testing.T) {
		admin := h.newAccount("fulltoken")
		h.grant(iam.RootGroup(), admin, "moderator")
		cl, err := h.auth.Verifier().Verify(ctx, h.login(admin).AccessToken)
		require.NoError(t, err)
		allowed, err := verify.Allow(ctx, h.auth, cl, iam.PermRootUsersBan, iam.RootGroup())
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
	resp := h.post("/passkeys/register/begin", map[string]any{}, token)
	require.Equal(h.t, http.StatusOK, resp.status, resp.String())
	var creation protocol.CredentialCreation
	resp.json(h.t, &creation)
	resp = h.post("/passkeys/register/finish", authn.Register(h.t, &creation), token)
	require.Equal(h.t, http.StatusOK, resp.status, resp.String())
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
	h := newHost(t, withHTTP(generousLimits), withEngine(withPasskeys))
	ctx := context.Background()
	victim := h.newAccount("p5victim")
	authn := h.registerPasskey(h.login(victim).AccessToken)
	resp := h.passkeyLogin(authn, 1)
	require.Equal(t, http.StatusOK, resp.status, resp.String())
	_, claims := splitToken(t, session(t, resp).AccessToken)
	require.Equal(t, iam.AssuranceLevelMFA, claims["acr"], "control: a passkey sign-in is MFA")
	sid, _ := claims["sid"].(string)
	require.NotEmpty(t, sid)
	// The attacker's copy of the session is older than the fresh-auth window.
	_, err := h.pool.Exec(ctx, `UPDATE profiles.refresh_sessions SET last_authenticated_at=now()-interval '20 minutes', mfa_authenticated_at=now()-interval '20 minutes' WHERE id=$1::uuid`, sid)
	require.NoError(t, err)
	resp = h.post("/step-up/password", map[string]string{"password": password}, h.sessionToken(victim.id, sid))
	require.Equal(t, http.StatusOK, resp.status, resp.String())
	stepped := session(t, resp).AccessToken
	_, claims = splitToken(t, stepped)
	require.Equal(t, iam.AssuranceLevelPassword, claims["acr"], "a password re-auth made a passkey session MFA-fresh")
	require.NotContains(t, claims["amr"], "mfa")
	require.Nil(t, claims["mfa_enrolled"])

	gate := func(opts verify.SensitiveOptions, token string) int {
		route := h.auth.Require(verify.Sensitive(opts)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })))
		r := httptest.NewRequest(http.MethodPost, "https://host.security.test/payout-address", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		route.ServeHTTP(w, r)
		return w.Code
	}
	require.Equal(t, http.StatusForbidden, gate(verify.SensitiveOptions{ACR: iam.AssuranceLevelMFA}, stepped))
	require.Equal(t, http.StatusForbidden, gate(verify.SensitiveOptions{AMR: []string{"mfa"}}, stepped))
	require.Equal(t, http.StatusNoContent, gate(verify.SensitiveOptions{}, stepped), "a password is this account's step-up")

	t.Run("control: a fresh passkey sign-in clears the MFA gate", func(t *testing.T) {
		resp := h.passkeyLogin(authn, 2)
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		require.Equal(t, http.StatusNoContent, gate(verify.SensitiveOptions{ACR: iam.AssuranceLevelMFA}, session(t, resp).AccessToken))
	})
}

// TestSecurityPasskeyHolderNeedsPasskey (P7): a holder of an MFA-required role
// whose only strong credential is a passkey signs in with it. A password never
// yields an enrollment token that would let whoever typed it enroll a factor
// of their own.
func TestSecurityPasskeyHolderNeedsPasskey(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withAccountRoles), withEngine(withPasskeys))
	ctx := context.Background()
	holder := h.newAccount("p7holder")
	authn := h.registerPasskey(h.login(holder).AccessToken)
	// The role came while 2FA was off, or was made MFA-required later.
	_, err := h.pool.Exec(ctx, `INSERT INTO profiles.group_user_roles(permission_group_id,user_id,role) VALUES($1::uuid,$2::uuid,'security')`, h.rootGroupID(), holder.id)
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
// password sign-in enrolls a factor. No other actor may reset an account.
func TestSecurityResetAccountMFA(t *testing.T) {
	optional := newHost(t, withHTTP(generousLimits), withEngine(withAccountRoles), withEngine(withPasskeys), withEngine(withDeviceKeys))
	ctx := context.Background()
	holder, lost, admin := optional.newAccount("r2holder"), optional.newAccount("r2lost"), optional.newAccount("r2admin")
	authn := optional.registerPasskey(optional.login(holder).AccessToken)
	laptop := newDeviceKey(t)
	require.Equal(t, http.StatusOK, optional.deviceEnroll(laptop, holder.email, nil).status)
	optional.enrollEmail2FA(lost)
	optional.grant(iam.RootGroup(), admin, "siteadmin")
	// The deployment then requires 2FA.
	cfg := optional.cfg.engine
	cfg.TwoFactor.Mode = iam.TwoFactorRequired
	runtime, err := authkit.New(ctx, cfg, optional.cfg.deps)
	require.NoError(t, err)
	t.Cleanup(runtime.Close)
	h := optional.fork(runtime)

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
	require.Len(t, h.mail.Messages(authtest.MFAReset, holder.email), 1)
	require.Equal(t, http.StatusUnauthorized, h.refresh(passkeySession.RefreshToken).status, "a session outlived the reset")
	require.NotEqual(t, http.StatusOK, h.passkeyLogin(authn, 2).status, "the passkey outlived the reset")
	keys, err := h.auth.ActiveDeviceKeys(ctx, holder.id)
	require.NoError(t, err)
	require.Empty(t, keys, "a device key outlived the reset")

	resp = signIn(holder)
	require.Equal(t, http.StatusForbidden, resp.status, resp.String())
	require.Equal(t, "2fa_enrollment_required", resp.errorCode())
	var body struct {
		Error struct {
			Metadata struct {
				TokenSet tokens `json:"token_set"`
			} `json:"metadata"`
		} `json:"error"`
	}
	resp.json(t, &body)
	_, resp = h.enrollTOTP(body.Error.Metadata.TokenSet.AccessToken)
	_, claims := splitToken(t, session(t, resp).AccessToken)
	require.Equal(t, iam.AssuranceLevelMFA, claims["acr"], "control: the enrolled factor signs in")

	t.Run("factors and backup codes go too", func(t *testing.T) {
		require.NoError(t, h.auth.ResetAccountMFA(ctx, lost.id))
		var factors, settings int
		require.NoError(t, h.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM profiles.mfa_factors WHERE user_id=$1::uuid), (SELECT count(*) FROM profiles.mfa_settings WHERE user_id=$1::uuid)`, lost.id).Scan(&factors, &settings))
		require.Zero(t, factors)
		require.Zero(t, settings)
		require.Equal(t, "2fa_enrollment_required", signIn(lost).errorCode())
	})
}
