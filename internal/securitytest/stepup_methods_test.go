package securitytest

import (
	"context"
	"net/http"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/passkeytest"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

// stepUpOffer is a 403 step_up_required's step_up_methods.
func stepUpOffer(t *testing.T, r response) []string {
	t.Helper()
	require.Equal(t, http.StatusForbidden, r.status, r.String())
	require.Equal(t, "step_up_required", r.errorCode(), r.String())
	var body struct {
		Error struct {
			Metadata struct {
				StepUpMethods []string `json:"step_up_methods"`
			} `json:"metadata"`
		} `json:"error"`
	}
	r.json(t, &body)
	return body.Error.Metadata.StepUpMethods
}

// sensitive is token's answer on a host route behind verify.Sensitive.
func (h *host) sensitive(token string) response {
	h.t.Helper()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	return serveHTTP(verify.Sensitive(h.auth)(ok), http.MethodPost)(h.t, token)
}

// passwordless signs email in with an emailed code and returns the session's
// access token.
func (h *host) passwordless(email string) string {
	h.t.Helper()
	resp := h.post("/passwordless/start", map[string]string{"identifier": email, "mode": "code"}, "")
	require.Less(h.t, resp.status, 300, resp.String())
	resp = h.post("/passwordless/confirm", map[string]string{"identifier": email, "code": h.verificationCode(email)}, "")
	return session(h.t, resp).AccessToken
}

// expire ends an ephemeral record now, as its TTL would.
func (h *host) expire(key string) {
	h.t.Helper()
	tag, err := h.pool.Exec(context.Background(), `UPDATE profiles.ephemeral_kv SET expires_at = now() - interval '1 second' WHERE key = $1`, key)
	require.NoError(h.t, err)
	require.EqualValues(h.t, 1, tag.RowsAffected(), key)
}

// TestSecurityStepUpByCode (A1): an account without a password or second
// factor steps up with a code sent to its proven address. The code is bound
// to the session that asked for it, single use and short-lived, proves only
// while the address stays proven, and never re-proves an account with a
// second factor.
func TestSecurityStepUpByCode(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withSMS, authtest.WithConfig(func(c *authkit.Config) { c.Registration.PasswordlessLogin = true }))
	ctx := context.Background()
	email := unique("codestepup") + "@security.test"
	u, err := h.auth.CreateUser(ctx, iam.NewUser{Email: email, Username: unique("codestepup"), EmailVerified: true})
	require.NoError(t, err)
	stale := authtest.StaleSession(t, h.auth, h.passwordless(email))
	_, claims := splitToken(t, stale)
	codeKey := "step-up:code:" + u.ID + ":" + claims["sid"].(string)
	send := func(token, channel string) response {
		return h.post("/me/step-up/code/send", map[string]string{"channel": channel}, token)
	}
	stepUp := func(token, code string) response {
		return h.post("/me/step-up/code", map[string]string{"code": code}, token)
	}
	requireCode := func(r response, code string) {
		t.Helper()
		require.Equal(t, http.StatusUnauthorized, r.status, r.String())
		require.Equal(t, code, r.errorCode(), r.String())
	}

	methods := stepUpOffer(t, h.do(request{method: http.MethodDelete, path: "/me", token: stale}))
	require.Equal(t, []string{"email"}, methods, "the proven email is the account's only step-up")
	resp := send(stale, "sms")
	require.Equal(t, http.StatusConflict, resp.status, "a code went to an address the account has not proven: %s", resp)
	require.Equal(t, "contact_not_verified", resp.errorCode())

	require.Equal(t, http.StatusAccepted, send(stale, "email").status)
	code := h.mail.Last(t, iam.MessageLoginCode, email).Code
	requireCode(stepUp(stale, wrongCode(code)), "invalid_code")
	other := authtest.StaleSession(t, h.auth, h.passwordless(email))
	requireCode(stepUp(other, code), "code_expired")

	resp = stepUp(stale, code)
	require.Equal(t, http.StatusOK, resp.status, resp.String())
	fresh := session(t, resp).AccessToken
	_, claims = splitToken(t, fresh)
	require.Contains(t, claims["amr"], "email")
	require.Equal(t, iam.AssuranceLevelPassword, claims["acr"], "a code is one factor")
	require.Equal(t, http.StatusNoContent, h.sensitive(fresh).status, "the step-up opens a host's Sensitive route")
	require.Equal(t, http.StatusForbidden, h.sensitive(stale).status)
	requireCode(stepUp(stale, code), "code_expired")

	t.Run("an expired code", func(t *testing.T) {
		require.Equal(t, http.StatusAccepted, send(stale, "email").status)
		code := h.mail.Last(t, iam.MessageLoginCode, email).Code
		h.expire(codeKey)
		requireCode(stepUp(stale, code), "code_expired")
	})

	t.Run("a code outlives its address's proof", func(t *testing.T) {
		require.Equal(t, http.StatusAccepted, send(stale, "email").status)
		code := h.mail.Last(t, iam.MessageLoginCode, email).Code
		proven := func(v bool) {
			_, err := h.pool.Exec(ctx, `UPDATE profiles.users SET email_verified = $2 WHERE id = $1::uuid`, u.ID, v)
			require.NoError(t, err)
		}
		proven(false)
		requireCode(stepUp(stale, code), "code_expired")
		proven(true)
	})

	t.Run("a texted code", func(t *testing.T) {
		const phone = "+14155550199"
		_, err := h.pool.Exec(ctx, `UPDATE profiles.users SET phone_number = $2, phone_verified = true WHERE id = $1::uuid`, u.ID, phone)
		require.NoError(t, err)
		methods := stepUpOffer(t, h.do(request{method: http.MethodDelete, path: "/me", token: stale}))
		require.Equal(t, []string{"email", "sms"}, methods)
		require.Equal(t, http.StatusAccepted, send(stale, "sms").status)
		resp := stepUp(stale, h.mail.Last(t, iam.MessageLoginCode, phone).Code)
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		_, claims := splitToken(t, session(t, resp).AccessToken)
		require.Contains(t, claims["amr"], "sms")
	})

	t.Run("a second factor enrolled after the code was sent", func(t *testing.T) {
		require.Equal(t, http.StatusAccepted, send(stale, "email").status)
		code := h.mail.Last(t, iam.MessageLoginCode, email).Code
		h.enrollTOTP(h.passwordless(email))
		require.Equal(t, []string{"2fa"}, stepUpOffer(t, stepUp(stale, code)), "a code re-proved an account with a second factor")
		require.Equal(t, []string{"2fa"}, stepUpOffer(t, send(stale, "email")))
	})
}

// TestSecurityStepUpByPasskey (A1): a passkey re-proves its account, second
// factor included, with an assertion over a ceremony bound to the session
// that began it, once. A sign-in ceremony never steps up a session, and a
// step-up ceremony never signs in.
func TestSecurityStepUpByPasskey(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withPasskeys))
	a := h.newAccount("passkeystepup")
	h.enrollEmail2FA(a)
	authn := h.registerPasskey(h.mfaSession(a))
	stale := authtest.StaleSession(t, h.auth, h.mfaSession(a))
	begin := func(token string) *protocol.CredentialAssertion {
		t.Helper()
		resp := h.post("/me/step-up/passkey/begin", nil, token)
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		var assertion protocol.CredentialAssertion
		resp.json(t, &assertion)
		require.Len(t, assertion.Response.AllowedCredentials, 1, "the account's own passkeys")
		return &assertion
	}
	stepUp := func(token string, body []byte) response { return h.post("/me/step-up/passkey", body, token) }
	requireCode := func(r response, code string) {
		t.Helper()
		require.Equal(t, http.StatusUnauthorized, r.status, r.String())
		require.Equal(t, code, r.errorCode(), r.String())
	}

	require.Equal(t, []string{"2fa", "passkey"}, stepUpOffer(t, h.post("/me/2fa/backup-codes", nil, stale)),
		"a password never re-proves an account with a second factor; a passkey does")

	requireCode(stepUp(stale, passkeytest.New(t, "http://localhost").Assert(t, begin(stale), 1)), "authentication_failed")
	resp := h.post("/passkeys/login/begin", map[string]any{}, "")
	require.Equal(t, http.StatusOK, resp.status, resp.String())
	var login protocol.CredentialAssertion
	resp.json(t, &login)
	requireCode(stepUp(stale, authn.Assert(t, &login, 1)), "challenge_mismatch")
	requireCode(stepUp(authtest.StaleSession(t, h.auth, h.mfaSession(a)), authn.Assert(t, begin(stale), 1)), "challenge_mismatch")
	resp = h.post("/passkeys/login/finish", authn.Assert(t, begin(stale), 1), "")
	require.Equal(t, http.StatusUnauthorized, resp.status, "a step-up ceremony signed in: %s", resp)
	require.NotContains(t, resp.String(), "access_token")
	expired := begin(stale)
	h.expire("passkey:" + expired.Response.Challenge.String())
	requireCode(stepUp(stale, authn.Assert(t, expired, 1)), "challenge_not_found")

	assertion := authn.Assert(t, begin(stale), 2)
	resp = stepUp(stale, assertion)
	require.Equal(t, http.StatusOK, resp.status, resp.String())
	fresh := session(t, resp).AccessToken
	_, claims := splitToken(t, fresh)
	require.Equal(t, iam.AssuranceLevelMFA, claims["acr"], "a passkey is multi-factor")
	require.Equal(t, http.StatusNoContent, h.sensitive(fresh).status)
	require.Equal(t, http.StatusOK, h.post("/me/2fa/backup-codes", nil, fresh).status)
	requireCode(stepUp(stale, assertion), "challenge_not_found")

	t.Run("an account without a passkey has none to begin", func(t *testing.T) {
		other := h.newAccount("nopasskey")
		resp := h.post("/me/step-up/passkey/begin", nil, h.login(other).AccessToken)
		require.Equal(t, http.StatusNotFound, resp.status, resp.String())
		require.Equal(t, "passkey_not_found", resp.errorCode())
	})
}
