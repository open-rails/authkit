package apitest_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/passkeytest"
)

// requireFactors asserts factors are exactly methods, defaultMethod the
// default, each addressed by its id, with a masked destination for a code
// sent by email or SMS.
func requireFactors(t *testing.T, factors []httpapi.TwoFactorFactor, methods []string, defaultMethod string) {
	t.Helper()
	got := make([]string, 0, len(factors))
	for _, f := range factors {
		require.NotEmpty(t, f.ID)
		require.Equal(t, f.Method == defaultMethod, f.IsDefault, f.Method)
		require.Equal(t, f.Method != "totp", f.Destination != nil, "an authenticator app alone has no destination")
		got = append(got, f.Method)
	}
	require.ElementsMatch(t, methods, got)
}

// security is the caller's GET /me/security.
func (f *factorFlow) security(token string) authflow.UserSecurity {
	f.t.Helper()
	var out authflow.UserSecurity
	require.NoError(f.t, json.Unmarshal([]byte(f.expect(http.StatusOK, f.request(http.MethodGet, "/me/security", token, nil)).raw), &out))
	return out
}

// A confirmed enrollment code verifies the enrolling session (#389); the
// account's other sessions still complete the second factor on refresh. An
// email factor proven on an email-first session is no second factor, and
// forced enrollment ends in a verified session.
func TestEnrollmentVerifiesEnrollingSession(t *testing.T) {
	auth, outbox := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.Registration.PasswordlessLogin = true }))
	signIn := func(f *factorFlow, u authtest.User) iam.TokenSet {
		f.t.Helper()
		return f.post("/password/login", map[string]any{"identifier": u.Email, "password": u.Password}).signedIn(f.t)
	}
	refresh := func(f *factorFlow, rt string) authAnswer {
		return f.post("/token", map[string]any{"grant_type": "refresh_token", "refresh_token": rt})
	}
	requireVerified := func(f *factorFlow, enabled authAnswer, enrolling iam.TokenSet, method string) {
		f.t.Helper()
		require.NotEmpty(f.t, enabled.BackupCodes)
		require.NotNil(f.t, enabled.Auth, enabled.raw)
		require.NotNil(f.t, enabled.Auth.FreshAuth, enabled.raw)
		require.Nil(f.t, enabled.tokens().RefreshToken, "step-up style response never rotates the refresh token")
		claims := accessClaims(f.t, enabled.tokens().AccessToken)
		require.ElementsMatch(f.t, []any{"pwd", method, "otp", "mfa"}, claims["amr"])
		require.Equal(f.t, iam.AssuranceLevelMFA, claims["acr"])
		require.Equal(f.t, true, claims["mfa_enrolled"])
		require.Contains(f.t, enabled.raw, `"fresh_auth"`)
		refreshed := refresh(f, *enrolling.RefreshToken).signedIn(f.t)
		f.session(refreshed, "pwd", method, "otp", "mfa")
		require.Equal(f.t, true, accessClaims(f.t, refreshed.AccessToken)["mfa_enrolled"])
	}
	// A refresh of a session that has not proven the new factor continues as a
	// sign-in: the second factor, not an error.
	requireChallenged := func(f *factorFlow, other iam.TokenSet, method string) {
		f.t.Helper()
		challenged := refresh(f, *other.RefreshToken).secondFactor(f.t)
		require.Equal(f.t, method, challenged.Factor.Method)
	}

	t.Run("totp", func(t *testing.T) {
		f := newFactorFlow(t, auth, outbox)
		u := authtest.NewUser(t, auth)
		enrolling, other := signIn(f, u), signIn(f, u)
		started := f.expect(http.StatusOK, f.request(http.MethodPost, "/me/2fa/setup", enrolling.AccessToken, map[string]any{"method": "totp"}))
		enabled := f.expect(http.StatusCreated, f.request(http.MethodPost, "/me/2fa/factors", enrolling.AccessToken,
			map[string]any{"method": "totp", "code": authtest.TOTPCode(t, started.Secret, time.Now())}))
		requireVerified(f, enabled, enrolling, "totp")
		requireChallenged(f, other, "totp")
	})

	t.Run("email", func(t *testing.T) {
		f := newFactorFlow(t, auth, outbox)
		u := authtest.NewUser(t, auth)
		enrolling, other := signIn(f, u), signIn(f, u)
		f.expect(http.StatusOK, f.request(http.MethodPost, "/me/2fa/setup", enrolling.AccessToken, map[string]any{"method": "email"}))
		code := f.code(iam.MessageVerification, u.Email)
		wrong := f.expect(http.StatusUnauthorized, f.request(http.MethodPost, "/me/2fa/factors", enrolling.AccessToken, map[string]any{"method": "email", "code": "000000x"}))
		require.Equal(t, "invalid_code", wrong.Error.Code)
		enabled := f.expect(http.StatusCreated, f.request(http.MethodPost, "/me/2fa/factors", enrolling.AccessToken, map[string]any{"method": "email", "code": code}))
		requireVerified(f, enabled, enrolling, "email")
		requireChallenged(f, other, "email")
	})

	t.Run("sms", func(t *testing.T) {
		f := newFactorFlow(t, auth, outbox)
		u := authtest.NewUser(t, auth)
		enrolling, other := signIn(f, u), signIn(f, u)
		const phone = "+15550100001"
		f.expect(http.StatusOK, f.request(http.MethodPost, "/me/2fa/setup", enrolling.AccessToken, map[string]any{"method": "sms", "phone_number": phone}))
		enabled := f.expect(http.StatusCreated, f.request(http.MethodPost, "/me/2fa/factors", enrolling.AccessToken,
			map[string]any{"method": "sms", "phone_number": phone, "code": f.code(iam.MessageVerification, phone)}))
		requireVerified(f, enabled, enrolling, "sms")
		requireChallenged(f, other, "sms")
	})

	t.Run("same channel is not a second factor", func(t *testing.T) {
		f := newFactorFlow(t, auth, outbox)
		u := authtest.NewUser(t, auth)
		f.expect(http.StatusAccepted, f.post("/passwordless/start", map[string]any{"identifier": u.Email, "mode": "code"}))
		session := f.post("/passwordless/confirm", map[string]any{"identifier": u.Email, "code": f.code(iam.MessageVerification, u.Email)}).signedIn(t)
		f.session(session, "email")
		f.expect(http.StatusOK, f.request(http.MethodPost, "/me/2fa/setup", session.AccessToken, map[string]any{"method": "email"}))
		enabled := f.expect(http.StatusCreated, f.request(http.MethodPost, "/me/2fa/factors", session.AccessToken,
			map[string]any{"method": "email", "code": f.code(iam.MessageVerification, u.Email)}))
		require.NotEmpty(t, enabled.BackupCodes)
		require.Nil(t, enabled.Auth, "the session stays email-only")
		challenged := refresh(f, *session.RefreshToken).secondFactor(t)
		require.Equal(t, u.ID, challenged.UserID)
		require.Equal(t, "backup_code", challenged.Factor.Method)
	})

	t.Run("forced email enrollment issues a verified session", func(t *testing.T) {
		forced := authtest.Replica(t, auth, authtest.WithConfig(func(c *authkit.Config) { c.TwoFactor.Mode = iam.TwoFactorRequired }))
		f := newFactorFlow(t, forced, outbox)
		u := authtest.NewUser(t, forced)
		grant := f.post("/password/login", map[string]any{"identifier": u.Email, "password": u.Password}).enrollment(t)
		require.Contains(t, grant.AllowedMethods, iam.TwoFactorEmail)
		restricted := grant.TokenSet.AccessToken
		f.expect(http.StatusOK, f.request(http.MethodPost, "/me/2fa/setup", restricted, map[string]any{"method": "email"}))
		enabled := f.expect(http.StatusCreated, f.request(http.MethodPost, "/me/2fa/factors", restricted,
			map[string]any{"method": "email", "code": f.code(iam.MessageVerification, u.Email)}))
		require.NotEmpty(t, enabled.BackupCodes)
		f.session(enabled.tokens(), "pwd", "email", "otp", "mfa")
		refreshed := refresh(f, *enabled.tokens().RefreshToken).signedIn(t)
		f.session(refreshed, "pwd", "email", "otp", "mfa")
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
		withAppLinks(c)
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
			link := deliveredLink(f.t, outbox.Last(t, iam.MessageVerification, email).Link, path, "email")
			first := f.post(confirm, map[string]any{"token": link})
			enrollment := first.enrollment(t)
			wireGolden(f.t, "mfa-enrollment", json.RawMessage(first.raw))
			require.False(t, first.Created, "created belongs to the complete sign-in")
			grant := enrollment.TokenSet
			require.NotEmpty(t, grant.AccessToken)
			require.Nil(t, grant.RefreshToken)
			require.NotContains(t, enrollment.AllowedMethods, iam.TwoFactorEmail, "two proofs sent to one mailbox are one factor")
			require.Contains(t, enrollment.AllowedMethods, iam.TwoFactorTOTP)
			require.ElementsMatch(t, []any{"email"}, accessClaims(f.t, grant.AccessToken)["amr"])
			denied := f.request(http.MethodGet, "/me", grant.AccessToken, nil)
			require.GreaterOrEqual(t, denied.status, 400, denied.raw)
			totp := f.expect(http.StatusOK, f.request(http.MethodPost, "/me/2fa/setup", grant.AccessToken, map[string]any{"method": "totp"}))
			enabled := f.expect(http.StatusCreated, f.request(http.MethodPost, "/me/2fa/factors", grant.AccessToken,
				map[string]any{"method": "totp", "code": authtest.TOTPCode(t, totp.Secret, time.Now())}))
			require.NotEmpty(t, enabled.BackupCodes)
			require.NotNil(t, enabled.Auth, enabled.raw)
			require.Equal(t, httpapi.AuthComplete, enabled.Auth.Status)
			require.NotNil(t, enabled.Auth.User)
			f.session(enabled.tokens(), "email", "totp", "otp", "mfa")
			replay := f.request(http.MethodPost, "/me/2fa/setup", grant.AccessToken, map[string]any{"method": "sms", "phone_number": "+15550100002"})
			require.GreaterOrEqual(t, replay.status, 400, replay.raw)

			// A fresh first factor now meets the enrolled second factor.
			var second authAnswer
			if passwordless {
				f.expect(http.StatusAccepted, f.post("/passwordless/start", map[string]any{"identifier": email, "mode": "both"}))
				second = f.post("/passwordless/confirm", map[string]any{"identifier": email, "code": f.code(iam.MessageVerification, email)})
			} else {
				second = f.post("/password/login", map[string]any{"identifier": email, "password": pass})
			}
			step := second.secondFactor(t)
			require.Equal(t, "totp", step.Factor.Method)
			require.Nil(t, step.Factor.Destination, "an authenticator app has no destination")
			wireGolden(f.t, "mfa-challenge", json.RawMessage(second.raw))
			methods := make([]string, 0, len(step.Factors))
			for _, factor := range step.Factors {
				methods = append(methods, factor.Method)
			}
			require.Contains(t, methods, "totp")
			wrong := map[string]any{"user_id": step.UserID, "challenge": step.Challenge + "x", "code": enabled.BackupCodes[0], "backup_code": true}
			f.expect(http.StatusUnauthorized, f.post("/2fa/verify", wrong))
			wrong["challenge"] = step.Challenge
			done := f.post("/2fa/verify", wrong)
			method := "pwd"
			if passwordless {
				method = "email"
			}
			f.session(done.signedIn(t), method, "backup_code", "otp", "mfa")
			require.Equal(t, step.UserID, done.User.ID)
			f.expect(http.StatusUnauthorized, f.post("/2fa/verify", wrong))

			// A password change voids the pending continuation.
			f.expect(http.StatusAccepted, f.post("/passwordless/start", map[string]any{"identifier": email, "mode": "both"}))
			pending := f.post("/passwordless/confirm", map[string]any{"token": outbox.Last(t, iam.MessageVerification, email).Token}).secondFactor(t)
			replacement := "Replacement-password-12345"
			_, err := auth.UpdateUser(ctx, iam.SystemActor(), pending.UserID, iam.UserUpdate{Password: &replacement})
			require.NoError(t, err)
			f.expect(http.StatusUnauthorized, f.post("/2fa/verify", map[string]any{"user_id": pending.UserID,
				"challenge": pending.Challenge, "code": enabled.BackupCodes[1], "backup_code": true}))
		})
	}

	f := newFactorFlow(t, auth, outbox)
	const phone = "+15550100003"
	f.expect(http.StatusAccepted, f.post("/passwordless/start", map[string]any{"identifier": phone, "mode": "code"}))
	phoneGrant := f.post("/passwordless/confirm", map[string]any{"identifier": phone, "code": f.code(iam.MessageVerification, phone)}).enrollment(t)
	require.NotContains(t, phoneGrant.AllowedMethods, iam.TwoFactorEmail, "an email-less account cannot enroll a mailbox factor")
	restricted := phoneGrant.TokenSet.AccessToken
	f.expect(http.StatusBadRequest, f.request(http.MethodPost, "/me/2fa/setup", restricted, map[string]any{"method": "email"}))
	phoneTOTP := f.expect(http.StatusOK, f.request(http.MethodPost, "/me/2fa/setup", restricted, map[string]any{"method": "totp"}))
	phoneSession := f.expect(http.StatusCreated, f.request(http.MethodPost, "/me/2fa/factors", restricted,
		map[string]any{"method": "totp", "code": authtest.TOTPCode(t, phoneTOTP.Secret, time.Now())}))
	f.session(phoneSession.tokens(), "sms", "totp", "otp", "mfa")
	require.True(t, phoneSession.Auth.Created, "the passwordless proof created the account")

	// Email-first plus email-only MFA offers a recovery key, never another code
	// to the same mailbox. A password first factor may use that email factor.
	const email = "same-channel@example.com"
	credentials := map[string]any{"identifier": email, "password": pass}
	u, err := auth.CreateUser(ctx, iam.NewUser{Email: email, Username: "samechannel", Password: pass})
	require.NoError(t, err)
	sent := len(outbox.Messages(iam.MessageVerification, ""))
	f.expect(http.StatusUnauthorized, f.post("/password/login", map[string]any{"identifier": email, "password": "wrong"}))
	require.Len(t, outbox.Messages(iam.MessageVerification, ""), sent, "a wrong password sends no code")
	verify := f.post("/password/login", credentials).step(t, httpapi.AuthVerificationRequired)
	require.NotNil(t, verify.Verification.PasswordProof, "the password sign-in hands back its proof")
	require.Equal(t, httpapi.VerificationStep{Identifier: email, Channel: "email", PasswordProof: verify.Verification.PasswordProof}, *verify.Verification)
	// Proving the address without that proof retires the password set before
	// it; the owner sets it again.
	verified, password := true, pass
	_, err = auth.UpdateUser(ctx, iam.SystemActor(), u.ID, iam.UserUpdate{EmailVerified: &verified, Password: &password})
	require.NoError(t, err)
	grant := f.post("/password/login", credentials).enrollment(t).TokenSet.AccessToken
	f.expect(http.StatusOK, f.request(http.MethodPost, "/me/2fa/setup", grant, map[string]any{"method": "email"}))
	backups := f.expect(http.StatusCreated, f.request(http.MethodPost, "/me/2fa/factors", grant,
		map[string]any{"method": "email", "code": f.code(iam.MessageVerification, email)})).BackupCodes
	require.NotEmpty(t, backups)
	f.expect(http.StatusAccepted, f.post("/passwordless/start", map[string]any{"identifier": email}))
	ch := f.post("/passwordless/confirm", map[string]any{"identifier": email, "code": f.code(iam.MessageVerification, email)}).secondFactor(t)
	require.Equal(t, "backup_code", ch.Factor.Method)
	require.Empty(t, ch.Factors, "the mailbox that proved the first factor is no second factor")
	f.expect(http.StatusUnauthorized, f.post("/2fa/verify", map[string]any{"user_id": u.ID, "challenge": ch.Challenge, "code": f.code(iam.MessageVerification, email)}))
	signed := f.post("/2fa/verify", map[string]any{"user_id": u.ID, "challenge": ch.Challenge, "code": backups[0], "backup_code": true})
	f.session(signed.signedIn(t), "email", "backup_code", "otp", "mfa")
	ch = f.post("/password/login", credentials).secondFactor(t)
	require.Equal(t, "email", ch.Factor.Method)
	require.NotNil(t, ch.Factor.Destination)
	require.NotContains(t, *ch.Factor.Destination, "same-channel", "the destination is masked")
	signed = f.post("/2fa/verify", map[string]any{"user_id": u.ID, "challenge": ch.Challenge, "code": f.code(iam.MessageLoginCode, email)})
	f.session(signed.signedIn(t), "pwd", "email", "otp", "mfa")

	// A fresh user-verifying passkey satisfies required 2FA and an
	// MFA-required role without a second traditional factor: the role came
	// while 2FA was off (a sibling deployment with 2FA disabled).
	bootstrap := authtest.Replica(t, auth, authtest.WithConfig(func(c *authkit.Config) { c.TwoFactor.Mode = iam.TwoFactorDisabled }))
	holder := authtest.NewUser(t, bootstrap)
	authtest.GrantRole(t, bootstrap, iam.RootGroup(), iam.UserSubject(holder.ID), admin)
	b := newFactorFlow(t, bootstrap, outbox)
	setup := authtest.SignIn(t, bootstrap, holder).AccessToken
	begun := b.expect(http.StatusOK, b.request(http.MethodPost, "/me/passkeys/register/begin", setup, nil))
	var creation protocol.CredentialCreation
	require.NoError(t, json.Unmarshal([]byte(begun.raw), &creation))
	authn := passkeytest.New(t, "https://app.example")
	b.expect(http.StatusCreated, b.request(http.MethodPost, "/me/passkeys/register/finish", setup, authn.Register(t, &creation)))
	started := f.expect(http.StatusOK, f.post("/passkeys/login/begin", map[string]any{}))
	var assertion protocol.CredentialAssertion
	require.NoError(t, json.Unmarshal([]byte(started.raw), &assertion))
	require.Empty(t, assertion.Response.AllowedCredentials)
	uv := f.post("/passkeys/login/finish", authn.Assert(t, &assertion, 1)).signedIn(t)
	f.session(uv, "swk", "mfa")
	require.Equal(t, true, accessClaims(f.t, uv.AccessToken)["mfa_enrolled"])
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
		f.expect(http.StatusOK, f.request(http.MethodPost, "/me/2fa/setup", token, map[string]any{"method": "email"}))
		f.expect(http.StatusCreated, f.request(http.MethodPost, "/me/2fa/factors", token, map[string]any{"method": "email", "code": f.code(iam.MessageVerification, u.Email)}))

		login := func() (map[string]any, string) {
			t.Helper()
			ch := f.post("/password/login", credentials(u)).secondFactor(t)
			require.Equal(t, "email", ch.Factor.Method)
			return map[string]any{"user_id": u.ID, "challenge": ch.Challenge}, f.code(iam.MessageLoginCode, u.Email)
		}
		with := func(body map[string]any, code string) map[string]any {
			out := map[string]any{"code": code}
			for k, v := range body {
				out[k] = v
			}
			return out
		}
		verify := func(body map[string]any, code string) authAnswer {
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
		f.session(verify(body, code).signedIn(t), "pwd", "email", "otp", "mfa")
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
		latest := verify(login()).signedIn(t)

		// Step-up on the signed-in session: same rules, the code CAS is the only guard.
		access := latest.AccessToken
		stepUp := func(code string) authAnswer {
			return f.request(http.MethodPost, "/me/step-up/2fa", access, map[string]any{"code": code})
		}
		send := func() string {
			t.Helper()
			f.expect(http.StatusAccepted, f.request(http.MethodPost, "/me/step-up/2fa/send", access, map[string]any{}))
			return f.code(iam.MessageLoginCode, u.Email)
		}
		code = send()
		f.expect(http.StatusUnauthorized, stepUp(wrong(code)))
		f.expect(http.StatusOK, stepUp(code))
		f.expect(http.StatusUnauthorized, stepUp(code))

		code = send()
		ok, denied = race(8, "/me/step-up/2fa", access, map[string]any{"code": code})
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
		errCode := func(status int, r authAnswer) string {
			t.Helper()
			return f.expect(status, r).Error.Code
		}

		// Enrollment (the email setup code): the same contract on POST
		// /me/2fa/factors.
		access := f.post("/password/login", credentials(u)).signedIn(t).AccessToken
		setup := func() {
			t.Helper()
			f.expect(http.StatusOK, f.request(http.MethodPost, "/me/2fa/setup", access, map[string]any{"method": "email"}))
		}
		enroll := func(code string) authAnswer {
			return f.request(http.MethodPost, "/me/2fa/factors", access, map[string]any{"method": "email", "code": code})
		}
		setup()
		code := f.code(iam.MessageVerification, u.Email)
		for range 4 {
			require.Equal(t, "invalid_code", errCode(http.StatusUnauthorized, enroll(wrong(code))))
		}
		require.Equal(t, "code_expired", errCode(http.StatusUnauthorized, enroll(wrong(code))))
		require.Equal(t, "code_expired", errCode(http.StatusUnauthorized, enroll(code)))
		require.Equal(t, "code_expired", errCode(http.StatusUnauthorized, enroll(wrong(code))))
		setup()
		code = f.code(iam.MessageVerification, u.Email)
		require.Equal(t, "invalid_code", errCode(http.StatusUnauthorized, enroll(wrong(code))))
		f.expect(http.StatusCreated, enroll(code))

		// Sign-in continuation.
		ch := f.post("/password/login", credentials(u)).secondFactor(t)
		require.NotEmpty(t, ch.Factors)
		verify := func(code string) authAnswer {
			return f.post("/2fa/verify", map[string]any{"user_id": u.ID, "challenge": ch.Challenge, "code": code})
		}
		code = f.code(iam.MessageLoginCode, u.Email)
		for range 4 {
			require.Equal(t, "invalid_code", errCode(http.StatusUnauthorized, verify(wrong(code))))
		}
		require.Equal(t, "code_expired", errCode(http.StatusUnauthorized, verify(wrong(code))))
		require.Equal(t, "code_expired", errCode(http.StatusUnauthorized, verify(code)))
		require.Equal(t, "code_expired", errCode(http.StatusUnauthorized, verify(wrong(code))))
		// A resend is the real next step: the same sign-in, its code at the
		// chosen factor.
		resent := f.post("/2fa/challenge", map[string]any{"user_id": u.ID, "challenge": ch.Challenge, "factor_id": ch.Factors[0].ID}).secondFactor(t)
		require.Equal(t, ch.Challenge, resent.Challenge)
		require.Equal(t, ch.Factors[0].ID, resent.Factor.ID)
		code = f.code(iam.MessageLoginCode, u.Email)
		require.Equal(t, "invalid_code", errCode(http.StatusUnauthorized, verify(wrong(code))))
		access = verify(code).signedIn(t).AccessToken

		// Step-up: never sent, then a resend restores retryable misses, then spent.
		stepUp := func(code string) authAnswer {
			return f.request(http.MethodPost, "/me/step-up/2fa", access, map[string]any{"code": code})
		}
		send := func() string {
			t.Helper()
			f.expect(http.StatusAccepted, f.request(http.MethodPost, "/me/step-up/2fa/send", access, map[string]any{}))
			return f.code(iam.MessageLoginCode, u.Email)
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
	require.NotContains(t, accessClaims(f.t, stale), "mfa_enrolled")
	for _, call := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/me/2fa/setup", map[string]any{"method": "totp"}},
		{http.MethodPost, "/me/2fa/factors", map[string]any{"method": "totp", "code": "123456"}},
		{http.MethodPost, "/me/2fa/setup", map[string]any{"method": "email"}},
		{http.MethodPost, "/me/2fa/setup", map[string]any{"method": "sms", "phone_number": "+15551234567"}},
		{http.MethodPatch, "/me/2fa/factors/" + uuid.NewString(), map[string]any{"default": true}},
		{http.MethodDelete, "/me/2fa/factors/" + uuid.NewString(), nil},
		{http.MethodDelete, "/me/2fa", nil},
	} {
		denied := f.expect(http.StatusForbidden, f.request(call.method, call.path, stale, call.body))
		require.Equal(t, "step_up_required", denied.Error.Code, call.path)
	}
	steppedUp := f.expect(http.StatusOK, f.request(http.MethodPost, "/me/step-up/password", stale, map[string]any{"password": u.Password}))
	require.Equal(t, httpapi.AuthComplete, steppedUp.Status, steppedUp.raw)
	require.Equal(t, u.ID, steppedUp.User.ID)
	stepped := steppedUp.tokens()
	require.NotEmpty(t, stepped.AccessToken)
	require.Equal(t, "Bearer", stepped.TokenType)
	require.Positive(t, stepped.ExpiresIn)
	claims := accessClaims(f.t, stepped.AccessToken)
	require.NotEmpty(t, claims["auth_time"])
	require.ElementsMatch(t, []any{"pwd"}, claims["amr"])
	require.Equal(t, iam.AssuranceLevelPassword, claims["acr"])
	require.NotNil(t, steppedUp.FreshAuth, steppedUp.raw)
	before := *steppedUp.FreshAuth
	pending := f.expect(http.StatusOK, f.request(http.MethodPost, "/me/2fa/setup", stepped.AccessToken, map[string]any{"method": "totp"}))
	require.NotEmpty(t, pending.Secret)
	require.Contains(t, pending.raw, "otpauth://totp/")
	// fresh_auth has whole seconds: enroll in a later second than the step-up.
	time.Sleep(time.Until(before.LastAuthenticatedAt.Add(time.Second + 100*time.Millisecond)))
	totpAt := func(secret string, counter int64) string {
		return authtest.TOTPCode(t, secret, time.Unix(counter*30, 0))
	}
	// Start with the previous accepted counter so the real step-up and sign-in
	// can follow without resetting replay state. Only an actually expired
	// counter may retry with a fresh code if this request crosses the window.
	enrolledStep := time.Now().Unix()/30 - 1
	enroll := func(counter int64) authAnswer {
		return f.request(http.MethodPost, "/me/2fa/factors", stepped.AccessToken, map[string]any{"method": "totp", "code": totpAt(pending.Secret, counter), "default": true})
	}
	enabled := enroll(enrolledStep)
	if enabled.status == http.StatusUnauthorized && enabled.Error.Code == "invalid_code" && time.Now().Unix()/30 > enrolledStep+1 {
		enrolledStep = time.Now().Unix() / 30
		enabled = enroll(enrolledStep)
	}
	f.expect(http.StatusCreated, enabled)
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
	require.NotNil(t, enabled.Auth, enabled.raw)
	require.NotNil(t, enabled.Auth.FreshAuth, enabled.raw)
	after := *enabled.Auth.FreshAuth
	require.True(t, after.LastAuthenticatedAt.After(*before.LastAuthenticatedAt), "the enrollment code is a fresh second-factor proof (#389)")
	require.ElementsMatch(t, slices.Concat(before.AuthMethods, []string{"totp", "otp", "mfa"}), after.AuthMethods)
	require.ElementsMatch(t, []any{"pwd", "totp", "otp", "mfa"}, accessClaims(f.t, enabled.tokens().AccessToken)["amr"])
	// Age the enrolling session so the step-up gates below apply again.
	current := authtest.StaleSession(t, auth, enabled.tokens().AccessToken)
	require.Equal(t, true, accessClaims(f.t, current)["mfa_enrolled"])
	denied := f.expect(http.StatusForbidden, f.request(http.MethodPost, "/me/2fa/backup-codes", current, nil))
	require.Equal(t, "step_up_required", denied.Error.Code)
	f.expect(http.StatusForbidden, f.request(http.MethodPost, "/me/2fa/setup", stepped.AccessToken, map[string]any{"method": "totp"}))

	security := f.security(current)
	status := security.TwoFactor
	require.True(t, status.Enabled)
	require.Equal(t, 10, status.BackupCodesRemaining)
	requireFactors(t, status.Factors, []string{"totp"}, "totp")
	factor := status.Factors[0]
	require.Equal(t, enabled.createdFactorID(t), factor.ID)
	require.Equal(t, []string{"2fa"}, security.StepUpMethods, "only a second factor re-proves an account that has one")
	for _, body := range []any{map[string]any{}, map[string]any{"factor_id": factor.ID}} {
		// An authenticator app needs no code sent.
		f.expect(http.StatusAccepted, f.request(http.MethodPost, "/me/step-up/2fa/send", current, body))
	}
	f.expect(http.StatusBadRequest, f.request(http.MethodPost, "/me/step-up/2fa/send", current, map[string]any{"method": "totp"}))
	f.expect(http.StatusNotFound, f.request(http.MethodPost, "/me/step-up/2fa/send", current, map[string]any{"factor_id": uuid.NewString()}))
	f.expect(http.StatusNotFound, f.request(http.MethodPost, "/me/step-up/2fa", current, map[string]any{"factor_id": uuid.NewString(), "code": "123456"}))
	for _, body := range []any{map[string]any{"method": "totp", "code": "123456"}, map[string]any{}} {
		f.expect(http.StatusBadRequest, f.request(http.MethodPost, "/me/step-up/2fa", current, body))
	}
	stepUpCounter, stepUpCode := nextCode(enrolledStep)
	steppedMFA := f.expect(http.StatusOK, f.request(http.MethodPost, "/me/step-up/2fa", current, map[string]any{"factor_id": factor.ID, "code": stepUpCode}))
	require.NotNil(t, steppedMFA.FreshAuth, steppedMFA.raw)
	mfa := steppedMFA.tokens()
	claims = accessClaims(f.t, mfa.AccessToken)
	require.NotEmpty(t, claims["auth_time"])
	require.ElementsMatch(t, []any{"pwd", "totp", "otp", "mfa"}, claims["amr"])
	require.Equal(t, iam.AssuranceLevelMFA, claims["acr"])
	passwordAgain := f.expect(http.StatusForbidden, f.request(http.MethodPost, "/me/step-up/password", mfa.AccessToken, map[string]any{"password": u.Password}))
	require.Equal(t, "step_up_required", passwordAgain.Error.Code, "a password never re-proves an account with a second factor")

	// A fresh factor proof permits management but cannot replace the factor:
	// the same factor and all its backup codes remain, and its app still
	// signs in below.
	replacement := f.expect(http.StatusOK, f.request(http.MethodPost, "/me/2fa/setup", mfa.AccessToken, map[string]any{"method": "totp"}))
	conflict := f.expect(http.StatusConflict, f.request(http.MethodPost, "/me/2fa/factors", mfa.AccessToken,
		map[string]any{"method": "totp", "code": authtest.TOTPCode(t, replacement.Secret, time.Now())}))
	require.Equal(t, "2fa_factor_exists", conflict.Error.Code)
	status = f.security(current).TwoFactor
	require.Len(t, status.Factors, 1)
	require.Equal(t, factor.ID, status.Factors[0].ID)
	require.Equal(t, 10, status.BackupCodesRemaining)
	updated := f.expect(http.StatusOK, f.request(http.MethodPatch, "/me/2fa/factors/"+factor.ID, mfa.AccessToken, map[string]any{"default": true}))
	require.Contains(t, updated.raw, `"is_default":true`)
	f.expect(http.StatusBadRequest, f.request(http.MethodPatch, "/me/2fa/factors/"+factor.ID, mfa.AccessToken, map[string]any{"default": false}))
	f.expect(http.StatusNotFound, f.request(http.MethodPatch, "/me/2fa/factors/"+uuid.NewString(), mfa.AccessToken, map[string]any{"default": true}))

	challenge := f.post("/password/login", map[string]any{"identifier": u.Email, "password": u.Password}).secondFactor(t)
	require.Equal(t, u.ID, challenge.UserID)
	require.Equal(t, "totp", challenge.Factor.Method)
	require.NotEmpty(t, challenge.Challenge)
	proof := map[string]any{"user_id": u.ID, "challenge": challenge.Challenge, "factor_id": factor.ID}
	selected := f.post("/2fa/challenge", proof).secondFactor(t)
	require.Equal(t, "totp", selected.Factor.Method)
	_, proof["code"] = nextCode(stepUpCounter)
	tokens := f.post("/2fa/verify", proof).signedIn(t)
	f.session(tokens, "pwd", "totp", "otp", "mfa")
	loginSID, _ := accessClaims(f.t, tokens.AccessToken)["sid"].(string)
	sessions, err := auth.Sessions(ctx, u.ID)
	require.NoError(t, err)
	var loginIP string
	for _, s := range sessions {
		if s.ID == loginSID {
			loginIP = *s.IP
		}
	}
	require.Equal(t, "192.0.2.1", loginIP, "MFA completion records the actual HTTP client IP")
	f.expect(http.StatusUnauthorized, f.post("/2fa/verify", proof))
	challenge = f.post("/password/login", map[string]any{"identifier": u.Email, "password": u.Password}).secondFactor(t)
	backup := f.post("/2fa/verify", map[string]any{"user_id": u.ID, "challenge": challenge.Challenge, "code": enabled.BackupCodes[0], "backup_code": true})
	f.session(backup.signedIn(t), "pwd", "backup_code", "otp", "mfa")

	// Only age the real MFA session; never inject proof or reset TOTP replay state.
	staleMFA := authtest.StaleSession(t, auth, tokens.AccessToken)
	denied = f.expect(http.StatusForbidden, f.request(http.MethodPost, "/me/2fa/backup-codes", staleMFA, nil))
	var staleResponse struct {
		Error struct {
			Metadata authflow.StepUpRequired `json:"metadata"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal([]byte(denied.raw), &staleResponse))
	require.Equal(t, "step_up_required", denied.Error.Code)
	require.Equal(t, []string{"2fa"}, staleResponse.Error.Metadata.StepUpMethods)
	require.Equal(t, status.Factors, staleResponse.Error.Metadata.Factors, "step-up and management show one factor shape")
	freshMFA := f.expect(http.StatusOK, f.request(http.MethodPost, "/me/step-up/2fa", staleMFA, map[string]any{"code": enabled.BackupCodes[1], "backup_code": true})).tokens()
	regenerated := f.expect(http.StatusOK, f.request(http.MethodPost, "/me/2fa/backup-codes", freshMFA.AccessToken, nil))
	require.Len(t, regenerated.BackupCodes, 10)

	// Removing the only factor turns MFA off; an absent factor is already
	// removed.
	f.expect(http.StatusNoContent, f.request(http.MethodDelete, "/me/2fa/factors/"+factor.ID, freshMFA.AccessToken, nil))
	f.expect(http.StatusNoContent, f.request(http.MethodDelete, "/me/2fa/factors/"+factor.ID, freshMFA.AccessToken, nil))
	status = f.security(freshMFA.AccessToken).TwoFactor
	require.False(t, status.Enabled)
	require.Empty(t, status.Factors)
}

// The sole root owner cannot turn off their second factor: the refusal keeps
// the factor and the role, never leaving the root group ownerless. With a
// second owner, turning it off removes only the disabling user's owner role.
func TestSoleRootOwnerCannotDisable2FA(t *testing.T) {
	auth, outbox := authtest.New(t)
	f := newFactorFlow(t, auth, outbox)
	ctx := t.Context()
	owner := iam.RootPersona().OwnerRole()
	can := func(u authtest.User) bool {
		ok, err := auth.Can(ctx, iam.UserActor(u.ID), iam.RootGroup(), ident.RootUsersRead)
		require.NoError(t, err)
		return ok
	}

	first := authtest.NewUser(t, auth)
	first.TOTP = authtest.EnrollTOTP(t, auth, first)
	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(first.ID), owner)
	token := authtest.SignIn(t, auth, first).AccessToken
	refused := f.expect(http.StatusConflict, f.request(http.MethodDelete, "/me/2fa", token, nil))
	require.Equal(t, "last_owner", refused.Error.Code)
	require.True(t, f.security(token).TwoFactor.Enabled, "the sole owner's 2FA stays on after a refused disable")
	require.True(t, can(first), "the sole owner keeps root:* after a refused disable")

	second := authtest.NewUser(t, auth)
	second.TOTP = authtest.EnrollTOTP(t, auth, second)
	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(second.ID), owner)
	f.expect(http.StatusNoContent, f.request(http.MethodDelete, "/me/2fa", token, nil))
	require.True(t, roleOfIn(t, auth, iam.RootGroup(), iam.UserSubject(first.ID)).IsZero(), "the owner role goes with the 2FA")
	require.Equal(t, owner, roleOfIn(t, auth, iam.RootGroup(), iam.UserSubject(second.ID)))
	require.False(t, can(first), "the first owner lost root:* with its 2FA")
	require.True(t, can(second), "the second owner is unaffected")
}
