package apitest_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/passkeytest"
)

// factorFlow drives a Client's sign-in, second-factor and credential routes
// as one browser would, and reads what its outbox delivered.
type factorFlow struct {
	t      *testing.T
	auth   *authkit.Client
	outbox *authtest.Outbox
	api    *api
}

func newFactorFlow(t *testing.T, auth *authkit.Client, outbox *authtest.Outbox) *factorFlow {
	t.Helper()
	return &factorFlow{t: t, auth: auth, outbox: outbox, api: newAPI(t, auth)}
}

// factorReply is an answer of those routes, decoded as far as the tests read
// it: a token set at the top level or under token_set, an enrollment's secret
// and backup codes, or an error with its continuation.
type factorReply struct {
	status int
	raw    string
	iam.TokenSet
	Tokens      iam.TokenSet `json:"token_set"`
	Secret      string       `json:"secret"`
	BackupCodes []string     `json:"backup_codes"`
	Error       struct {
		Code     string `json:"code"`
		Metadata struct {
			UserID           string       `json:"user_id"`
			Challenge        string       `json:"challenge"`
			Method           string       `json:"method"`
			TokenSet         iam.TokenSet `json:"token_set"`
			AllowedMethods   []string     `json:"allowed_methods"`
			AvailableFactors []struct {
				ID     string `json:"id"`
				Method string `json:"method"`
			} `json:"available_factors"`
		} `json:"metadata"`
	} `json:"error"`
}

func (f *factorFlow) request(method, path, token string, body any) factorReply {
	f.t.Helper()
	res := f.api.do(request{method: method, path: path, token: token, body: body})
	out := factorReply{status: res.status, raw: string(res.body)}
	if len(res.body) > 0 && res.header.Get("Content-Type") == "application/json" {
		require.NoError(f.t, json.Unmarshal(res.body, &out), out.raw)
	}
	return out
}

func (f *factorFlow) post(path string, body any) factorReply {
	f.t.Helper()
	return f.request(http.MethodPost, path, "", body)
}

func (f *factorFlow) expect(status int, r factorReply) factorReply {
	f.t.Helper()
	require.Equal(f.t, status, r.status, r.raw)
	return r
}

// code is the code of the newest kind message to to; the test fails without one.
func (f *factorFlow) code(kind authtest.Kind, to string) string {
	f.t.Helper()
	code := f.outbox.Last(f.t, kind, to).Code
	require.NotEmpty(f.t, code)
	return code
}

// session asserts tokens are a whole session: a refresh token, an access token
// the Client verifies with exactly amr, and a working GET /me.
func (f *factorFlow) session(tokens iam.TokenSet, amr ...string) {
	f.t.Helper()
	require.NotEmpty(f.t, tokens.RefreshToken)
	require.Greater(f.t, tokens.ExpiresIn, int64(0))
	claims, err := f.auth.Verifier().Verify(f.t.Context(), tokens.AccessToken)
	require.NoError(f.t, err)
	require.NotEmpty(f.t, claims.UserID)
	require.ElementsMatch(f.t, amr, claims.AMR)
	f.expect(http.StatusOK, f.request(http.MethodGet, "/me", tokens.AccessToken, nil))
}

// claims decodes token's claims without verifying it, after matching its
// header to the access-header golden.
func (f *factorFlow) claims(token string) jwt.MapClaims {
	f.t.Helper()
	claims := jwt.MapClaims{}
	parsed, _, err := jwt.NewParser().ParseUnverified(token, claims)
	require.NoError(f.t, err)
	f.wireGolden("access-header", parsed.Header)
	return claims
}

// deliveredLink checks a delivered link lands on the host's frontend path with
// the ready status, channel and token in its fragment, and returns the token.
func (f *factorFlow) deliveredLink(raw, path, channel string) string {
	f.t.Helper()
	u, err := url.Parse(raw)
	require.NoError(f.t, err)
	require.Equal(f.t, "https://app.example"+path, u.Scheme+"://"+u.Host+u.Path)
	require.Empty(f.t, u.RawQuery)
	fragment, err := url.ParseQuery(u.Fragment)
	require.NoError(f.t, err)
	require.Equal(f.t, "ready", fragment.Get("status"))
	require.Equal(f.t, channel, fragment.Get("channel"))
	require.NotEmpty(f.t, fragment.Get("token"))
	return fragment.Get("token")
}

// wireGolden matches value's JSON to testdata/wire/<name>.json: documented
// fields and types are required, additional keys allowed. "$string" is a
// non-empty string, "$text" any string, "$number" a positive number,
// "$strings" a non-empty string array, and a one-object array an item schema.
func (f *factorFlow) wireGolden(name string, value any) {
	t := f.t
	t.Helper()
	fixture, err := os.ReadFile(filepath.Join("testdata", "wire", name+".json"))
	require.NoError(t, err)
	var expected, actual any
	require.NoError(t, json.Unmarshal(fixture, &expected))
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(encoded, &actual))
	var match func(any, any, string)
	match = func(want, got any, path string) {
		switch want := want.(type) {
		case map[string]any:
			require.IsType(t, want, got, path)
			fields := got.(map[string]any)
			for key, value := range want {
				require.Contains(t, fields, key, path)
				match(value, fields[key], path+"."+key)
			}
		case string:
			switch want {
			case "$string":
				require.IsType(t, "", got, path)
				require.NotEmpty(t, got, path)
			case "$text":
				require.IsType(t, "", got, path)
			case "$number":
				require.IsType(t, float64(0), got, path)
				require.Greater(t, got.(float64), float64(0), path)
			case "$strings":
				require.IsType(t, []any{}, got, path)
				require.NotEmpty(t, got, path)
				for _, item := range got.([]any) {
					match("$string", item, path+"[]")
				}
			default:
				require.Equal(t, want, got, path)
			}
		case []any:
			if len(want) == 1 {
				if _, object := want[0].(map[string]any); object {
					require.IsType(t, []any{}, got, path)
					require.NotEmpty(t, got, path)
					for _, item := range got.([]any) {
						match(want[0], item, path+"[]")
					}
					return
				}
			}
			require.Equal(t, want, got, path)
		default:
			require.Equal(t, want, got, path)
		}
	}
	match(expected, actual, name)
}

// factorStepUpOptions is the step_up_2fa object of GET /me and of a
// step_up_required refusal.
type factorStepUpOptions struct {
	Methods       []string `json:"methods"`
	DefaultMethod string   `json:"default_method"`
	Options       []struct {
		ID             string `json:"id"`
		Method         string `json:"method"`
		IsDefault      bool   `json:"is_default"`
		VerificationID string `json:"verification_id"`
	} `json:"options"`
}

// require asserts the options offer exactly methods, defaulting to
// defaultMethod, and never name a factor by id.
func (o factorStepUpOptions) require(t *testing.T, methods []string, defaultMethod string) {
	t.Helper()
	require.ElementsMatch(t, methods, o.Methods)
	require.Equal(t, defaultMethod, o.DefaultMethod)
	seen := map[string]bool{}
	for _, option := range o.Options {
		require.Empty(t, option.ID)
		require.NotEmpty(t, option.Method)
		seen[option.Method] = true
		if option.Method == defaultMethod {
			require.True(t, option.IsDefault)
		}
		if option.Method == "email" || option.Method == "sms" {
			require.NotEmpty(t, option.VerificationID)
		}
	}
	for _, method := range methods {
		require.True(t, seen[method], "missing 2FA option %q", method)
	}
}

// A confirmed enrollment code verifies the enrolling session (#389); the
// account's other sessions still complete the second factor on refresh. An
// email factor proven on an email-first session is no second factor, and
// forced enrollment ends in a verified session.
func TestEnrollmentVerifiesEnrollingSession(t *testing.T) {
	auth, outbox := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.Registration.PasswordlessLogin = true }))
	signIn := func(f *factorFlow, u authtest.User) factorReply {
		f.t.Helper()
		return f.expect(http.StatusOK, f.post("/password/login", map[string]any{"identifier": u.Email, "password": u.Password}))
	}
	refresh := func(f *factorFlow, rt string) factorReply {
		return f.post("/token", map[string]any{"grant_type": "refresh_token", "refresh_token": rt})
	}
	requireVerified := func(f *factorFlow, enabled, enrolling factorReply, method string) {
		f.t.Helper()
		require.NotEmpty(f.t, enabled.BackupCodes)
		require.Empty(f.t, enabled.Tokens.RefreshToken, "step-up style response never rotates the refresh token")
		claims := f.claims(enabled.Tokens.AccessToken)
		require.ElementsMatch(f.t, []any{"pwd", method, "otp", "mfa"}, claims["amr"])
		require.Equal(f.t, iam.AssuranceLevelMFA, claims["acr"])
		require.Equal(f.t, true, claims["mfa_enrolled"])
		require.Contains(f.t, enabled.raw, `"fresh_auth"`)
		refreshed := f.expect(http.StatusOK, refresh(f, enrolling.RefreshToken))
		f.session(refreshed.TokenSet, "pwd", method, "otp", "mfa")
		require.Equal(f.t, true, f.claims(refreshed.AccessToken)["mfa_enrolled"])
	}
	requireChallenged := func(f *factorFlow, other factorReply, method string) {
		f.t.Helper()
		challenged := f.expect(http.StatusForbidden, refresh(f, other.RefreshToken))
		require.Equal(f.t, "2fa_required", challenged.Error.Code)
		require.Equal(f.t, method, challenged.Error.Metadata.Method)
	}

	t.Run("totp", func(t *testing.T) {
		f := newFactorFlow(t, auth, outbox)
		u := authtest.NewUser(t, auth)
		enrolling, other := signIn(f, u), signIn(f, u)
		started := f.expect(http.StatusOK, f.request(http.MethodPost, "/user/2fa", enrolling.AccessToken, map[string]any{"method": "totp"}))
		enabled := f.expect(http.StatusOK, f.request(http.MethodPost, "/user/2fa", enrolling.AccessToken,
			map[string]any{"method": "totp", "code": authtest.TOTPCode(t, started.Secret, time.Now())}))
		requireVerified(f, enabled, enrolling, "totp")
		requireChallenged(f, other, "totp")
	})

	t.Run("email", func(t *testing.T) {
		f := newFactorFlow(t, auth, outbox)
		u := authtest.NewUser(t, auth)
		enrolling, other := signIn(f, u), signIn(f, u)
		f.expect(http.StatusAccepted, f.request(http.MethodPost, "/user/2fa", enrolling.AccessToken, map[string]any{"method": "email"}))
		code := f.code(authtest.Verification, u.Email)
		wrong := f.expect(http.StatusUnauthorized, f.request(http.MethodPost, "/user/2fa", enrolling.AccessToken, map[string]any{"method": "email", "code": "000000x"}))
		require.Equal(t, "invalid_code", wrong.Error.Code)
		enabled := f.expect(http.StatusOK, f.request(http.MethodPost, "/user/2fa", enrolling.AccessToken, map[string]any{"method": "email", "code": code}))
		requireVerified(f, enabled, enrolling, "email")
		requireChallenged(f, other, "email")
	})

	t.Run("sms", func(t *testing.T) {
		f := newFactorFlow(t, auth, outbox)
		u := authtest.NewUser(t, auth)
		enrolling, other := signIn(f, u), signIn(f, u)
		const phone = "+15550100001"
		f.expect(http.StatusAccepted, f.request(http.MethodPost, "/user/2fa", enrolling.AccessToken, map[string]any{"method": "sms", "phone_number": phone}))
		enabled := f.expect(http.StatusOK, f.request(http.MethodPost, "/user/2fa", enrolling.AccessToken,
			map[string]any{"method": "sms", "phone_number": phone, "code": f.code(authtest.Verification, phone)}))
		requireVerified(f, enabled, enrolling, "sms")
		requireChallenged(f, other, "sms")
	})

	t.Run("same channel is not a second factor", func(t *testing.T) {
		f := newFactorFlow(t, auth, outbox)
		u := authtest.NewUser(t, auth)
		f.expect(http.StatusAccepted, f.post("/passwordless/start", map[string]any{"identifier": u.Email, "mode": "code"}))
		session := f.expect(http.StatusOK, f.post("/passwordless/confirm", map[string]any{"identifier": u.Email, "code": f.code(authtest.Verification, u.Email)}))
		f.session(session.Tokens, "email")
		f.expect(http.StatusAccepted, f.request(http.MethodPost, "/user/2fa", session.Tokens.AccessToken, map[string]any{"method": "email"}))
		enabled := f.expect(http.StatusOK, f.request(http.MethodPost, "/user/2fa", session.Tokens.AccessToken,
			map[string]any{"method": "email", "code": f.code(authtest.Verification, u.Email)}))
		require.NotEmpty(t, enabled.BackupCodes)
		require.Empty(t, enabled.Tokens.AccessToken, "the session stays email-only")
		challenged := f.expect(http.StatusForbidden, refresh(f, session.Tokens.RefreshToken))
		require.Equal(t, "2fa_required", challenged.Error.Code)
		require.Equal(t, u.ID, challenged.Error.Metadata.UserID)
		require.Equal(t, "backup_code", challenged.Error.Metadata.Method)
	})

	t.Run("forced email enrollment issues a verified session", func(t *testing.T) {
		forced := authtest.Replica(t, auth, authtest.WithConfig(func(c *authkit.Config) { c.TwoFactor.Mode = iam.TwoFactorRequired }))
		f := newFactorFlow(t, forced, outbox)
		u := authtest.NewUser(t, forced)
		grant := f.expect(http.StatusForbidden, f.post("/password/login", map[string]any{"identifier": u.Email, "password": u.Password}))
		require.Equal(t, "2fa_enrollment_required", grant.Error.Code)
		require.Contains(t, grant.Error.Metadata.AllowedMethods, "email")
		restricted := grant.Error.Metadata.TokenSet.AccessToken
		f.expect(http.StatusAccepted, f.request(http.MethodPost, "/user/2fa", restricted, map[string]any{"method": "email"}))
		enabled := f.expect(http.StatusOK, f.request(http.MethodPost, "/user/2fa", restricted,
			map[string]any{"method": "email", "code": f.code(authtest.Verification, u.Email)}))
		require.NotEmpty(t, enabled.BackupCodes)
		f.session(enabled.Tokens, "pwd", "email", "otp", "mfa")
		refreshed := f.expect(http.StatusOK, refresh(f, enabled.Tokens.RefreshToken))
		f.session(refreshed.TokenSet, "pwd", "email", "otp", "mfa")
	})
}

// TestAuthenticationContinuationWorkflow: under required 2FA a first factor
// (a registration proof, a passwordless link or code, a phone) reaches only a
// restricted enrollment token. Enrolling an independent factor with it ends in
// a verified session; later sign-ins complete the second factor, and a
// password change voids pending ones. A mailbox is one factor however many
// proofs it receives. A user-verifying passkey is MFA by itself.
func TestAuthenticationContinuationWorkflow(t *testing.T) {
	rbac := authkit.NewRoles()
	admin := rbac.Root.Role("admin", rbac.Root.All())
	auth, outbox := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Registration.PasswordlessLogin, c.Registration.PasswordlessAutoRegistration = true, true
		c.Registration.Verification = iam.RegistrationVerificationRequired
		c.TwoFactor.Mode = iam.TwoFactorRequired
		c.Passkeys = authkit.PasskeyConfig{RPID: "app.example", Origins: []string{"https://app.example"}}
		c.Roles = rbac
		c.Frontend = authkit.FrontendConfig{BaseURL: "https://app.example", VerifyPath: "/verify", PasswordlessPath: "/login/link", PasswordResetPath: "/reset"}
	}))
	ctx := t.Context()
	const pass = "Correct-horse-battery-1"
	for _, passwordless := range []bool{false, true} {
		t.Run(fmt.Sprint("passwordless=", passwordless), func(t *testing.T) {
			f := newFactorFlow(t, auth, outbox)
			email := fmt.Sprintf("continuation-%t@example.com", passwordless)
			start, confirm, path := "/register", "/verify/confirm", "/verify"
			payload := map[string]any{"identifier": email}
			if passwordless {
				start, confirm, path = "/passwordless/start", "/passwordless/confirm", "/login/link"
				payload["mode"] = "both"
			} else {
				payload["username"] = "continuation"
				payload["password"] = pass
			}
			f.expect(http.StatusAccepted, f.post(start, payload))
			link := f.deliveredLink(outbox.Last(t, authtest.Verification, email).Link, path, "email")
			first := f.expect(http.StatusForbidden, f.post(confirm, map[string]any{"token": link}))
			require.Equal(t, "2fa_enrollment_required", first.Error.Code)
			f.wireGolden("mfa-enrollment", json.RawMessage(first.raw))
			grant := first.Error.Metadata.TokenSet
			require.NotEmpty(t, grant.AccessToken)
			require.Empty(t, grant.RefreshToken)
			require.NotContains(t, first.Error.Metadata.AllowedMethods, "email", "two proofs sent to one mailbox are one factor")
			require.Contains(t, first.Error.Metadata.AllowedMethods, "totp")
			require.ElementsMatch(t, []any{"email"}, f.claims(grant.AccessToken)["amr"])
			denied := f.request(http.MethodGet, "/me", grant.AccessToken, nil)
			require.GreaterOrEqual(t, denied.status, 400, denied.raw)
			totp := f.expect(http.StatusOK, f.request(http.MethodPost, "/user/2fa", grant.AccessToken, map[string]any{"method": "totp"}))
			enabled := f.expect(http.StatusOK, f.request(http.MethodPost, "/user/2fa", grant.AccessToken,
				map[string]any{"method": "totp", "code": authtest.TOTPCode(t, totp.Secret, time.Now())}))
			require.NotEmpty(t, enabled.BackupCodes)
			f.session(enabled.Tokens, "email", "totp", "otp", "mfa")
			replay := f.request(http.MethodPost, "/user/2fa", grant.AccessToken, map[string]any{"method": "sms", "phone_number": "+15550100002"})
			require.GreaterOrEqual(t, replay.status, 400, replay.raw)

			// A fresh first factor now meets the enrolled second factor.
			var second factorReply
			if passwordless {
				f.expect(http.StatusAccepted, f.post("/passwordless/start", map[string]any{"identifier": email, "mode": "both"}))
				second = f.expect(http.StatusForbidden, f.post("/passwordless/confirm", map[string]any{"identifier": email, "code": f.code(authtest.Verification, email)}))
			} else {
				second = f.expect(http.StatusForbidden, f.post("/password/login", map[string]any{"identifier": email, "password": pass}))
			}
			require.Equal(t, "2fa_required", second.Error.Code)
			require.Equal(t, "totp", second.Error.Metadata.Method)
			f.wireGolden("mfa-challenge", json.RawMessage(second.raw))
			methods := make([]string, 0, len(second.Error.Metadata.AvailableFactors))
			for _, factor := range second.Error.Metadata.AvailableFactors {
				methods = append(methods, factor.Method)
			}
			require.Contains(t, methods, "totp")
			wrong := map[string]any{"user_id": second.Error.Metadata.UserID, "challenge": second.Error.Metadata.Challenge + "x", "code": enabled.BackupCodes[0], "backup_code": true}
			f.expect(http.StatusUnauthorized, f.post("/2fa/verify", wrong))
			wrong["challenge"] = second.Error.Metadata.Challenge
			done := f.expect(http.StatusOK, f.post("/2fa/verify", wrong))
			method := "pwd"
			if passwordless {
				method = "email"
			}
			f.session(done.TokenSet, method, "backup_code", "otp", "mfa")
			f.expect(http.StatusUnauthorized, f.post("/2fa/verify", wrong))

			// A password change voids the pending continuation.
			f.expect(http.StatusAccepted, f.post("/passwordless/start", map[string]any{"identifier": email, "mode": "both"}))
			pending := f.expect(http.StatusForbidden, f.post("/passwordless/confirm", map[string]any{"token": outbox.Last(t, authtest.Verification, email).Token}))
			replacement := "Replacement-password-12345"
			_, err := auth.UpdateUser(ctx, iam.SystemActor(), pending.Error.Metadata.UserID, iam.UserUpdate{Password: &replacement})
			require.NoError(t, err)
			f.expect(http.StatusUnauthorized, f.post("/2fa/verify", map[string]any{"user_id": pending.Error.Metadata.UserID,
				"challenge": pending.Error.Metadata.Challenge, "code": enabled.BackupCodes[1], "backup_code": true}))
		})
	}

	f := newFactorFlow(t, auth, outbox)
	const phone = "+15550100003"
	f.expect(http.StatusAccepted, f.post("/passwordless/start", map[string]any{"identifier": phone, "mode": "code"}))
	phoneGrant := f.expect(http.StatusForbidden, f.post("/passwordless/confirm", map[string]any{"identifier": phone, "code": f.code(authtest.Verification, phone)}))
	require.Equal(t, "2fa_enrollment_required", phoneGrant.Error.Code)
	require.NotContains(t, phoneGrant.Error.Metadata.AllowedMethods, "email", "an email-less account cannot enroll a mailbox factor")
	restricted := phoneGrant.Error.Metadata.TokenSet.AccessToken
	f.expect(http.StatusBadRequest, f.request(http.MethodPost, "/user/2fa", restricted, map[string]any{"method": "email"}))
	phoneTOTP := f.expect(http.StatusOK, f.request(http.MethodPost, "/user/2fa", restricted, map[string]any{"method": "totp"}))
	phoneSession := f.expect(http.StatusOK, f.request(http.MethodPost, "/user/2fa", restricted,
		map[string]any{"method": "totp", "code": authtest.TOTPCode(t, phoneTOTP.Secret, time.Now())}))
	f.session(phoneSession.Tokens, "sms", "totp", "otp", "mfa")

	// Email-first plus email-only MFA offers a recovery key, never another code
	// to the same mailbox. A password first factor may use that email factor.
	const email = "same-channel@example.com"
	credentials := map[string]any{"identifier": email, "password": pass}
	u, err := auth.CreateUser(ctx, iam.NewUser{Email: email, Username: "samechannel", Password: pass})
	require.NoError(t, err)
	sent := len(outbox.Messages(authtest.Verification, ""))
	f.expect(http.StatusUnauthorized, f.post("/password/login", map[string]any{"identifier": email, "password": "wrong"}))
	require.Len(t, outbox.Messages(authtest.Verification, ""), sent, "a wrong password sends no code")
	verify := f.expect(http.StatusForbidden, f.post("/password/login", credentials))
	require.Equal(t, "verification_required", verify.Error.Code)
	// Proving the address retires the password set before the proof; the
	// owner sets it again.
	verified, password := true, pass
	_, err = auth.UpdateUser(ctx, iam.SystemActor(), u.ID, iam.UserUpdate{EmailVerified: &verified, Password: &password})
	require.NoError(t, err)
	grant := f.expect(http.StatusForbidden, f.post("/password/login", credentials))
	require.Equal(t, "2fa_enrollment_required", grant.Error.Code)
	f.expect(http.StatusAccepted, f.request(http.MethodPost, "/user/2fa", grant.Error.Metadata.TokenSet.AccessToken, map[string]any{"method": "email"}))
	backups := f.expect(http.StatusOK, f.request(http.MethodPost, "/user/2fa", grant.Error.Metadata.TokenSet.AccessToken,
		map[string]any{"method": "email", "code": f.code(authtest.Verification, email)})).BackupCodes
	require.NotEmpty(t, backups)
	f.expect(http.StatusAccepted, f.post("/passwordless/start", map[string]any{"identifier": email}))
	ch := f.expect(http.StatusForbidden, f.post("/passwordless/confirm", map[string]any{"identifier": email, "code": f.code(authtest.Verification, email)}))
	require.Equal(t, "backup_code", ch.Error.Metadata.Method)
	f.expect(http.StatusUnauthorized, f.post("/2fa/verify", map[string]any{"user_id": u.ID, "challenge": ch.Error.Metadata.Challenge, "code": f.code(authtest.Verification, email)}))
	signed := f.expect(http.StatusOK, f.post("/2fa/verify", map[string]any{"user_id": u.ID, "challenge": ch.Error.Metadata.Challenge, "code": backups[0], "backup_code": true}))
	f.session(signed.TokenSet, "email", "backup_code", "otp", "mfa")
	ch = f.expect(http.StatusForbidden, f.post("/password/login", credentials))
	require.Equal(t, "email", ch.Error.Metadata.Method)
	signed = f.expect(http.StatusOK, f.post("/2fa/verify", map[string]any{"user_id": u.ID, "challenge": ch.Error.Metadata.Challenge, "code": f.code(authtest.LoginCode, email)}))
	f.session(signed.TokenSet, "pwd", "email", "otp", "mfa")

	// A fresh user-verifying passkey satisfies required 2FA and an
	// MFA-required role without a second traditional factor: the role came
	// while 2FA was off (a sibling deployment with 2FA disabled).
	bootstrap := authtest.Replica(t, auth, authtest.WithConfig(func(c *authkit.Config) { c.TwoFactor.Mode = iam.TwoFactorDisabled }))
	holder := authtest.NewUser(t, bootstrap)
	authtest.GrantRole(t, bootstrap, iam.RootGroup(), iam.UserSubject(holder.ID), admin)
	b := newFactorFlow(t, bootstrap, outbox)
	setup := authtest.SignIn(t, bootstrap, holder).AccessToken
	begun := b.expect(http.StatusOK, b.request(http.MethodPost, "/passkeys/register/begin", setup, map[string]any{}))
	var creation protocol.CredentialCreation
	require.NoError(t, json.Unmarshal([]byte(begun.raw), &creation))
	authn := passkeytest.New(t, "https://app.example")
	b.expect(http.StatusOK, b.request(http.MethodPost, "/passkeys/register/finish", setup, authn.Register(t, &creation)))
	started := f.expect(http.StatusOK, f.post("/passkeys/login/begin", map[string]any{}))
	var assertion protocol.CredentialAssertion
	require.NoError(t, json.Unmarshal([]byte(started.raw), &assertion))
	require.Empty(t, assertion.Response.AllowedCredentials)
	uv := f.expect(http.StatusOK, f.post("/passkeys/login/finish", authn.Assert(t, &assertion, 1)))
	f.session(uv.TokenSet, "swk", "mfa")
	require.Equal(t, true, f.claims(uv.AccessToken)["mfa_enrolled"])
}

// TestTwoFactorCodeLifecycle: an emailed code survives a typo, is spent
// exactly once however many requests race for it, and the fifth miss burns
// it (#387), at sign-in and step-up alike. A miss that leaves the code live
// is invalid_code; no live code (burned, spent, never sent) is code_expired
// until a new one is sent, at enrollment too. Expiry by the database clock is
// engine TestTwoFactorCodeExpiresByDatabaseClock.
func TestTwoFactorCodeLifecycle(t *testing.T) {
	auth, outbox := authtest.New(t)
	wrong := func(code string) string {
		if code[0] == '0' {
			return "1" + code[1:]
		}
		return "0" + code[1:]
	}
	credentials := func(u authtest.User) map[string]any {
		return map[string]any{"identifier": u.Email, "password": u.Password}
	}

	t.Run("a wrong guess keeps the code", func(t *testing.T) {
		f := newFactorFlow(t, auth, outbox)
		u := authtest.NewUser(t, auth)
		token := authtest.SignIn(t, auth, u).AccessToken
		f.expect(http.StatusAccepted, f.request(http.MethodPost, "/user/2fa", token, map[string]any{"method": "email"}))
		f.expect(http.StatusOK, f.request(http.MethodPost, "/user/2fa", token, map[string]any{"method": "email", "code": f.code(authtest.Verification, u.Email)}))

		login := func() (map[string]any, string) {
			t.Helper()
			ch := f.expect(http.StatusForbidden, f.post("/password/login", credentials(u)))
			require.Equal(t, "email", ch.Error.Metadata.Method)
			return map[string]any{"user_id": u.ID, "challenge": ch.Error.Metadata.Challenge}, f.code(authtest.LoginCode, u.Email)
		}
		with := func(body map[string]any, code string) map[string]any {
			out := map[string]any{"code": code}
			for k, v := range body {
				out[k] = v
			}
			return out
		}
		verify := func(body map[string]any, code string) factorReply {
			return f.post("/2fa/verify", with(body, code))
		}
		race := func(n int, path, token string, body map[string]any) (ok, denied int) {
			t.Helper()
			var mu sync.Mutex
			var wg sync.WaitGroup
			var errs []error
			for range n {
				wg.Go(func() {
					res, err := f.api.send(request{method: http.MethodPost, path: path, token: token, body: body})
					mu.Lock()
					defer mu.Unlock()
					switch {
					case err != nil:
						errs = append(errs, err)
					case res.status == http.StatusOK:
						ok++
					case res.status == http.StatusUnauthorized:
						denied++
					}
				})
			}
			wg.Wait()
			require.Empty(t, errs)
			return ok, denied
		}

		// Sign-in: a typo keeps the code.
		body, code := login()
		f.expect(http.StatusUnauthorized, verify(body, wrong(code)))
		signed := f.expect(http.StatusOK, verify(body, code))
		f.session(signed.TokenSet, "pwd", "email", "otp", "mfa")
		f.expect(http.StatusUnauthorized, verify(body, code))

		// Sign-in: concurrent correct submissions succeed exactly once.
		body, code = login()
		ok, denied := race(8, "/2fa/verify", "", with(body, code))
		require.Equal(t, 1, ok)
		require.Equal(t, 7, denied)

		// Sign-in: four misses leave the code usable; the fifth burns it.
		body, code = login()
		for range 4 {
			f.expect(http.StatusUnauthorized, verify(body, wrong(code)))
		}
		f.expect(http.StatusOK, verify(body, code))
		body, code = login()
		for range 5 {
			f.expect(http.StatusUnauthorized, verify(body, wrong(code)))
		}
		require.Equal(t, "code_expired", f.expect(http.StatusUnauthorized, verify(body, code)).Error.Code)
		// The default 3-session cap has evicted the first sessions by now.
		latest := f.expect(http.StatusOK, verify(login()))

		// Step-up on the signed-in session: same rules, the code CAS is the only guard.
		access := latest.TokenSet.AccessToken
		stepUp := func(code string) factorReply {
			return f.request(http.MethodPost, "/step-up/2fa", access, map[string]any{"code": code})
		}
		send := func() string {
			t.Helper()
			ch := f.expect(http.StatusForbidden, f.request(http.MethodPost, "/step-up/2fa", access, map[string]any{}))
			require.Equal(t, "2fa_required", ch.Error.Code)
			return f.code(authtest.LoginCode, u.Email)
		}
		code = send()
		f.expect(http.StatusUnauthorized, stepUp(wrong(code)))
		f.expect(http.StatusOK, stepUp(code))
		f.expect(http.StatusUnauthorized, stepUp(code))

		code = send()
		ok, denied = race(8, "/step-up/2fa", access, map[string]any{"code": code})
		require.Equal(t, 1, ok)
		require.Equal(t, 7, denied)

		code = send()
		for range 5 {
			f.expect(http.StatusUnauthorized, stepUp(wrong(code)))
		}
		require.Equal(t, "code_expired", f.expect(http.StatusUnauthorized, stepUp(code)).Error.Code)
		code = send()
		f.expect(http.StatusOK, stepUp(code))
	})

	t.Run("no live code is code_expired", func(t *testing.T) {
		f := newFactorFlow(t, auth, outbox)
		u := authtest.NewUser(t, auth)
		errCode := func(status int, r factorReply) string {
			t.Helper()
			return f.expect(status, r).Error.Code
		}

		// Enrollment (the email setup code): the same contract on POST /user/2fa.
		access := f.expect(http.StatusOK, f.post("/password/login", credentials(u))).AccessToken
		enroll := func(code string) factorReply {
			body := map[string]any{"method": "email"}
			if code != "" {
				body["code"] = code
			}
			return f.request(http.MethodPost, "/user/2fa", access, body)
		}
		f.expect(http.StatusAccepted, enroll(""))
		code := f.code(authtest.Verification, u.Email)
		for range 4 {
			require.Equal(t, "invalid_code", errCode(http.StatusUnauthorized, enroll(wrong(code))))
		}
		require.Equal(t, "code_expired", errCode(http.StatusUnauthorized, enroll(wrong(code))))
		require.Equal(t, "code_expired", errCode(http.StatusUnauthorized, enroll(code)))
		require.Equal(t, "code_expired", errCode(http.StatusUnauthorized, enroll(wrong(code))))
		f.expect(http.StatusAccepted, enroll(""))
		code = f.code(authtest.Verification, u.Email)
		require.Equal(t, "invalid_code", errCode(http.StatusUnauthorized, enroll(wrong(code))))
		f.expect(http.StatusOK, enroll(code))

		// Sign-in continuation.
		ch := f.expect(http.StatusForbidden, f.post("/password/login", credentials(u)))
		require.Equal(t, "2fa_required", ch.Error.Code)
		require.NotEmpty(t, ch.Error.Metadata.AvailableFactors)
		verify := func(code string) factorReply {
			return f.post("/2fa/verify", map[string]any{"user_id": u.ID, "challenge": ch.Error.Metadata.Challenge, "code": code})
		}
		code = f.code(authtest.LoginCode, u.Email)
		for range 4 {
			require.Equal(t, "invalid_code", errCode(http.StatusUnauthorized, verify(wrong(code))))
		}
		require.Equal(t, "code_expired", errCode(http.StatusUnauthorized, verify(wrong(code))))
		require.Equal(t, "code_expired", errCode(http.StatusUnauthorized, verify(code)))
		require.Equal(t, "code_expired", errCode(http.StatusUnauthorized, verify(wrong(code))))
		f.expect(http.StatusForbidden, f.post("/2fa/challenge", map[string]any{"user_id": u.ID, "challenge": ch.Error.Metadata.Challenge,
			"factor_id": ch.Error.Metadata.AvailableFactors[0].ID}))
		code = f.code(authtest.LoginCode, u.Email)
		require.Equal(t, "invalid_code", errCode(http.StatusUnauthorized, verify(wrong(code))))
		access = f.expect(http.StatusOK, verify(code)).AccessToken

		// Step-up: never sent, then a resend restores retryable misses, then spent.
		stepUp := func(code string) factorReply {
			return f.request(http.MethodPost, "/step-up/2fa", access, map[string]any{"code": code})
		}
		send := func() string {
			t.Helper()
			require.Equal(t, "2fa_required", errCode(http.StatusForbidden, f.request(http.MethodPost, "/step-up/2fa", access, map[string]any{})))
			return f.code(authtest.LoginCode, u.Email)
		}
		require.Equal(t, "code_expired", errCode(http.StatusUnauthorized, stepUp("123456")))
		code = send()
		require.Equal(t, "invalid_code", errCode(http.StatusUnauthorized, stepUp(wrong(code))))
		code = send()
		require.Equal(t, "invalid_code", errCode(http.StatusUnauthorized, stepUp(wrong(code))))
		f.expect(http.StatusOK, stepUp(code))
		require.Equal(t, "code_expired", errCode(http.StatusUnauthorized, stepUp(code)))
	})
}

// freshAuth is the session state a step-up or enrollment answer reports.
type freshAuth struct {
	FreshAuth struct {
		LastAuthenticatedAt time.Time `json:"last_authenticated_at"`
		AuthMethods         []string  `json:"auth_methods"`
	} `json:"fresh_auth"`
}

// TestFactorManagementWorkflow: managing second factors needs a recent
// sign-in. A password step-up gives one until the account has a factor; from
// then on only the factor (or a backup code) re-proves the session. The
// enrollment code itself re-proves the enrolling session. A second
// authenticator app never replaces the first.
func TestFactorManagementWorkflow(t *testing.T) {
	auth, outbox := authtest.New(t)
	f := newFactorFlow(t, auth, outbox)
	ctx := t.Context()
	u := authtest.NewUser(t, auth)
	stale := authtest.StaleSession(t, auth, authtest.SignIn(t, auth, u).AccessToken)
	require.NotContains(t, f.claims(stale), "mfa_enrolled")
	for _, body := range []any{
		map[string]any{"method": "totp"}, map[string]any{"method": "totp", "code": "123456"},
		map[string]any{"method": "email"}, map[string]any{"method": "sms", "phone_number": "+15551234567"},
		map[string]any{"default": true, "factor_id": "anything"},
	} {
		denied := f.expect(http.StatusForbidden, f.request(http.MethodPost, "/user/2fa", stale, body))
		require.Equal(t, "step_up_required", denied.Error.Code)
	}
	steppedUp := f.expect(http.StatusOK, f.request(http.MethodPost, "/step-up/password", stale, map[string]any{"password": u.Password}))
	stepped := steppedUp.Tokens
	require.NotEmpty(t, stepped.AccessToken)
	require.Equal(t, "Bearer", stepped.TokenType)
	require.Positive(t, stepped.ExpiresIn)
	claims := f.claims(stepped.AccessToken)
	require.NotEmpty(t, claims["auth_time"])
	require.ElementsMatch(t, []any{"pwd"}, claims["amr"])
	require.Equal(t, iam.AssuranceLevelPassword, claims["acr"])
	var before, after freshAuth
	require.NoError(t, json.Unmarshal([]byte(steppedUp.raw), &before))
	pending := f.expect(http.StatusOK, f.request(http.MethodPost, "/user/2fa", stepped.AccessToken, map[string]any{"method": "totp"}))
	require.NotEmpty(t, pending.Secret)
	require.Contains(t, pending.raw, "otpauth://totp/")
	// fresh_auth has whole seconds: enroll in a later second than the step-up.
	time.Sleep(time.Until(before.FreshAuth.LastAuthenticatedAt.Add(time.Second + 100*time.Millisecond)))
	totpAt := func(secret string, counter int64) string { return authtest.TOTPCode(t, secret, time.Unix(counter*30, 0)) }
	// Start with the previous accepted counter so the real step-up and sign-in
	// can follow without resetting replay state. Only an actually expired
	// counter may retry with a fresh code if this request crosses the window.
	enrolledStep := time.Now().Unix()/30 - 1
	enroll := func(counter int64) factorReply {
		return f.request(http.MethodPost, "/user/2fa", stepped.AccessToken, map[string]any{"method": "totp", "code": totpAt(pending.Secret, counter), "default": true})
	}
	enabled := enroll(enrolledStep)
	if enabled.status == http.StatusUnauthorized && enabled.Error.Code == "invalid_code" && time.Now().Unix()/30 > enrolledStep+1 {
		enrolledStep = time.Now().Unix() / 30
		enabled = enroll(enrolledStep)
	}
	f.expect(http.StatusOK, enabled)
	nextCode := func(after int64) (int64, string) {
		t.Helper()
		counter := max(time.Now().Unix()/30, after+1)
		// The server accepts the next counter, but never a later one. This
		// wait is needed only after the expiry retry consumed a newer counter.
		if delay := time.Until(time.Unix((counter-1)*30, 0)); delay > 0 {
			require.LessOrEqual(t, delay, 35*time.Second)
			t.Logf("waiting %s for an unused TOTP counter", delay)
			time.Sleep(delay)
		}
		return counter, totpAt(pending.Secret, counter)
	}
	require.Len(t, enabled.BackupCodes, 10)
	require.NoError(t, json.Unmarshal([]byte(enabled.raw), &after))
	require.True(t, after.FreshAuth.LastAuthenticatedAt.After(before.FreshAuth.LastAuthenticatedAt), "the enrollment code is a fresh second-factor proof (#389)")
	require.ElementsMatch(t, slices.Concat(before.FreshAuth.AuthMethods, []string{"totp", "otp", "mfa"}), after.FreshAuth.AuthMethods)
	require.ElementsMatch(t, []any{"pwd", "totp", "otp", "mfa"}, f.claims(enabled.Tokens.AccessToken)["amr"])
	// Age the enrolling session so the step-up gates below apply again.
	current := authtest.StaleSession(t, auth, enabled.Tokens.AccessToken)
	require.Equal(t, true, f.claims(current)["mfa_enrolled"])
	denied := f.expect(http.StatusForbidden, f.request(http.MethodPost, "/user/2fa/backup-codes", current, map[string]any{}))
	require.Equal(t, "step_up_required", denied.Error.Code)
	f.expect(http.StatusForbidden, f.request(http.MethodPost, "/user/2fa", stepped.AccessToken, map[string]any{"method": "totp"}))

	var status struct {
		Method               string `json:"method"`
		BackupCodesRemaining int    `json:"backup_codes_remaining"`
		Factors              []struct {
			ID        string `json:"id"`
			Method    string `json:"method"`
			IsDefault bool   `json:"is_default"`
		} `json:"factors"`
	}
	listed := f.expect(http.StatusOK, f.request(http.MethodGet, "/user/2fa", current, nil))
	require.NoError(t, json.Unmarshal([]byte(listed.raw), &status))
	require.Equal(t, "totp", status.Method)
	require.Equal(t, 10, status.BackupCodesRemaining)
	require.Len(t, status.Factors, 1)
	factor := status.Factors[0]
	require.NotEmpty(t, factor.ID)
	require.Equal(t, "totp", factor.Method)
	require.True(t, factor.IsDefault)
	var me struct {
		Security struct {
			StepUpMethods []string            `json:"step_up_methods"`
			StepUp2FA     factorStepUpOptions `json:"step_up_2fa"`
		} `json:"security"`
	}
	profile := f.expect(http.StatusOK, f.request(http.MethodGet, "/me", current, nil))
	require.NoError(t, json.Unmarshal([]byte(profile.raw), &me))
	require.Contains(t, me.Security.StepUpMethods, "2fa")
	me.Security.StepUp2FA.require(t, []string{"totp"}, "totp")
	for _, body := range []any{map[string]any{}, map[string]any{"method": "totp"}} {
		challenge := f.expect(http.StatusForbidden, f.request(http.MethodPost, "/step-up/2fa", current, body))
		require.Equal(t, "totp", challenge.Error.Metadata.Method)
		require.NotContains(t, challenge.raw, `"factor"`)
	}
	for _, body := range []any{map[string]any{"method": "bad"}, map[string]any{"factor_id": factor.ID}} {
		f.expect(http.StatusBadRequest, f.request(http.MethodPost, "/step-up/2fa", current, body))
	}
	stepUpCounter, stepUpCode := nextCode(enrolledStep)
	mfa := f.expect(http.StatusOK, f.request(http.MethodPost, "/step-up/2fa", current, map[string]any{"code": stepUpCode})).Tokens
	claims = f.claims(mfa.AccessToken)
	require.NotEmpty(t, claims["auth_time"])
	require.ElementsMatch(t, []any{"pwd", "totp", "otp", "mfa"}, claims["amr"])
	require.Equal(t, iam.AssuranceLevelMFA, claims["acr"])
	passwordAgain := f.expect(http.StatusForbidden, f.request(http.MethodPost, "/step-up/password", mfa.AccessToken, map[string]any{"password": u.Password}))
	require.Equal(t, "step_up_required", passwordAgain.Error.Code, "a password never re-proves an account with a second factor")

	// A fresh factor proof permits management but cannot replace the factor:
	// the same factor and all its backup codes remain, and its app still
	// signs in below.
	replacement := f.expect(http.StatusOK, f.request(http.MethodPost, "/user/2fa", mfa.AccessToken, map[string]any{"method": "totp"}))
	conflict := f.expect(http.StatusConflict, f.request(http.MethodPost, "/user/2fa", mfa.AccessToken,
		map[string]any{"method": "totp", "code": authtest.TOTPCode(t, replacement.Secret, time.Now())}))
	require.Equal(t, "2fa_factor_exists", conflict.Error.Code)
	listed = f.expect(http.StatusOK, f.request(http.MethodGet, "/user/2fa", current, nil))
	require.NoError(t, json.Unmarshal([]byte(listed.raw), &status))
	require.Len(t, status.Factors, 1)
	require.Equal(t, factor.ID, status.Factors[0].ID)
	require.Equal(t, 10, status.BackupCodesRemaining)
	f.expect(http.StatusNoContent, f.request(http.MethodPost, "/user/2fa", mfa.AccessToken, map[string]any{"factor_id": factor.ID, "default": true}))
	listed = f.expect(http.StatusOK, f.request(http.MethodGet, "/user/2fa", current, nil))
	require.NoError(t, json.Unmarshal([]byte(listed.raw), &status))
	require.Equal(t, "totp", status.Method)

	challenge := f.expect(http.StatusForbidden, f.post("/password/login", map[string]any{"identifier": u.Email, "password": u.Password}))
	require.Equal(t, u.ID, challenge.Error.Metadata.UserID)
	require.Equal(t, "totp", challenge.Error.Metadata.Method)
	require.NotEmpty(t, challenge.Error.Metadata.Challenge)
	proof := map[string]any{"user_id": u.ID, "challenge": challenge.Error.Metadata.Challenge, "factor_id": factor.ID}
	selected := f.expect(http.StatusForbidden, f.post("/2fa/challenge", proof))
	require.Equal(t, "totp", selected.Error.Metadata.Method)
	_, proof["code"] = nextCode(stepUpCounter)
	tokens := f.expect(http.StatusOK, f.post("/2fa/verify", proof)).TokenSet
	f.session(tokens, "pwd", "totp", "otp", "mfa")
	loginSID, _ := f.claims(tokens.AccessToken)["sid"].(string)
	sessions, err := auth.Sessions(ctx, u.ID)
	require.NoError(t, err)
	var loginIP string
	for _, s := range sessions {
		if s.ID == loginSID {
			loginIP = s.IP
		}
	}
	require.Equal(t, "192.0.2.1", loginIP, "MFA completion records the actual HTTP client IP")
	f.expect(http.StatusUnauthorized, f.post("/2fa/verify", proof))
	challenge = f.expect(http.StatusForbidden, f.post("/password/login", map[string]any{"identifier": u.Email, "password": u.Password}))
	backup := f.expect(http.StatusOK, f.post("/2fa/verify", map[string]any{"user_id": u.ID, "challenge": challenge.Error.Metadata.Challenge, "code": enabled.BackupCodes[0], "backup_code": true}))
	f.session(backup.TokenSet, "pwd", "backup_code", "otp", "mfa")

	// Only age the real MFA session; never inject proof or reset TOTP replay state.
	staleMFA := authtest.StaleSession(t, auth, tokens.AccessToken)
	denied = f.expect(http.StatusForbidden, f.request(http.MethodPost, "/user/2fa/backup-codes", staleMFA, map[string]any{}))
	var staleResponse struct {
		Error struct {
			Metadata struct {
				StepUpMethods []string            `json:"step_up_methods"`
				StepUp2FA     factorStepUpOptions `json:"step_up_2fa"`
			} `json:"metadata"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal([]byte(denied.raw), &staleResponse))
	require.Equal(t, "step_up_required", denied.Error.Code)
	require.Contains(t, staleResponse.Error.Metadata.StepUpMethods, "2fa")
	staleResponse.Error.Metadata.StepUp2FA.require(t, []string{"totp"}, "totp")
	freshMFA := f.expect(http.StatusOK, f.request(http.MethodPost, "/step-up/2fa", staleMFA, map[string]any{"code": enabled.BackupCodes[1], "backup_code": true})).Tokens
	regenerated := f.expect(http.StatusOK, f.request(http.MethodPost, "/user/2fa/backup-codes", freshMFA.AccessToken, map[string]any{}))
	require.Len(t, regenerated.BackupCodes, 10)
}

// The sole root owner cannot turn off their second factor: the refusal keeps
// the factor and the role, never leaving the root group ownerless. With a
// second owner, turning it off removes only the disabling user's owner role.
func TestSoleRootOwnerCannotDisable2FA(t *testing.T) {
	auth, outbox := authtest.New(t)
	f := newFactorFlow(t, auth, outbox)
	ctx := t.Context()
	owner := iam.RootPersona.OwnerRole()
	can := func(u authtest.User) bool {
		ok, err := auth.Can(ctx, iam.UserActor(u.ID), iam.RootGroup(), iam.PermRootUsersRead)
		require.NoError(t, err)
		return ok
	}

	first := authtest.NewUser(t, auth)
	first.TOTP = authtest.EnrollTOTP(t, auth, first)
	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(first.ID), owner)
	token := authtest.SignIn(t, auth, first).AccessToken
	refused := f.expect(http.StatusConflict, f.request(http.MethodDelete, "/user/2fa", token, nil))
	require.Equal(t, "last_owner", refused.Error.Code)
	var status struct {
		Enabled bool `json:"enabled"`
	}
	settings := f.expect(http.StatusOK, f.request(http.MethodGet, "/user/2fa", token, nil))
	require.NoError(t, json.Unmarshal([]byte(settings.raw), &status))
	require.True(t, status.Enabled, "the sole owner's 2FA stays on after a refused disable")
	require.True(t, can(first), "the sole owner keeps root:* after a refused disable")

	second := authtest.NewUser(t, auth)
	second.TOTP = authtest.EnrollTOTP(t, auth, second)
	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(second.ID), owner)
	disabled := f.expect(http.StatusOK, f.request(http.MethodDelete, "/user/2fa", token, nil))
	var removed struct {
		RemovedRoles []struct {
			Persona string `json:"persona"`
			Role    string `json:"role"`
		} `json:"removed_roles"`
	}
	require.NoError(t, json.Unmarshal([]byte(disabled.raw), &removed))
	require.Len(t, removed.RemovedRoles, 1, "only the owner role goes")
	require.Equal(t, iam.RootPersona.String(), removed.RemovedRoles[0].Persona)
	require.Equal(t, owner.Name(), removed.RemovedRoles[0].Role)
	require.False(t, can(first), "the first owner lost root:* with its 2FA")
	require.True(t, can(second), "the second owner is unaffected")
}
