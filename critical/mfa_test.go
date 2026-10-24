package critical_test

import (
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

type factorResult struct {
	Factor struct {
		ID      string `json:"id"`
		Method  string `json:"method"`
		Default bool   `json:"default"`
	} `json:"factor"`
	Backup []string      `json:"backup_codes"`
	Auth   *signInResult `json:"auth"`
}
type loginChallenge struct {
	UserID    string `json:"user_id"`
	Challenge string `json:"challenge"`
	Factor    struct {
		ID     string `json:"id"`
		Method string `json:"method"`
	} `json:"factor"`
}

func mfaFixture(t *testing.T, mode iam.TwoFactorMode) *fixture {
	return newFixture(t, authtest.WithConfig(func(c *authkit.Config) { c.TwoFactor.Mode = mode }))
}
func (f *fixture) totp(t *testing.T, token string) (string, factorResult) {
	t.Helper()
	r := f.call(t, "POST", "/me/2fa/setup", token, map[string]string{"method": "totp"})
	r.want(t, http.StatusOK, "")
	var setup struct {
		Secret string `json:"secret"`
		URI    string `json:"otpauth_uri"`
	}
	decode(t, r.body, &setup)
	uri, err := url.Parse(setup.URI)
	noError(t, err)
	if setup.Secret == "" || uri.Scheme != "otpauth" || uri.Host != "totp" || uri.Query().Get("secret") != setup.Secret {
		t.Fatal("setup did not publish a usable authenticator enrollment")
	}
	// The client fixture's RFC6238 computation has an independent known vector.
	if authtest.TOTPCode(t, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", time.Unix(59, 0)) != "287082" {
		t.Fatal("TOTP client fixture disagrees with RFC vector")
	}
	r = f.call(t, "POST", "/me/2fa/factors", token, map[string]any{"method": "totp", "code": authtest.TOTPCode(t, setup.Secret, time.Now()), "default": true})
	r.want(t, http.StatusCreated, "")
	var created factorResult
	decode(t, r.body, &created)
	if created.Factor.ID == "" || created.Factor.Method != "totp" || len(created.Backup) == 0 {
		t.Fatal("factor enrollment did not create its first factor and recovery material")
	}
	return setup.Secret, created
}
func (f *fixture) challenge(t *testing.T, u authtest.User) loginChallenge {
	t.Helper()
	r := f.call(t, "POST", "/password/login", "", map[string]string{"identifier": u.Email, "password": u.Password})
	r.want(t, http.StatusOK, "")
	var result struct {
		Status string         `json:"status"`
		Tokens *iam.TokenSet  `json:"token_set"`
		Step   loginChallenge `json:"second_factor"`
	}
	decode(t, r.body, &result)
	if result.Status != "second_factor_required" || result.Tokens != nil || result.Step.UserID != u.ID || result.Step.Challenge == "" {
		t.Fatalf("password bypassed enrolled MFA: %s", r.body)
	}
	return result.Step
}
func enrollmentToken(t *testing.T, r response) string {
	t.Helper()
	r.want(t, http.StatusOK, "")
	var result struct {
		Status     string        `json:"status"`
		Tokens     *iam.TokenSet `json:"token_set"`
		Enrollment struct {
			Tokens iam.TokenSet `json:"token_set"`
		} `json:"enrollment"`
	}
	decode(t, r.body, &result)
	if result.Status != "enrollment_required" || result.Tokens != nil || result.Enrollment.Tokens.AccessToken == "" {
		t.Fatalf("MFA-required login did not restrict its enrollment token: %s", r.body)
	}
	return result.Enrollment.Tokens.AccessToken
}
func factorSession(t *testing.T, created factorResult, user string) iam.TokenSet {
	t.Helper()
	if created.Auth == nil || created.Auth.Status != "complete" || created.Auth.Tokens == nil || created.Auth.User == nil || created.Auth.User.ID != user {
		t.Fatal("successful independent factor did not return the expected authenticated session")
	}
	return *created.Auth.Tokens
}

func TestCriticalMFA(t *testing.T) {
	t.Run("AK-J07-C01_required_enrollment_has_no_ordinary_authority", func(t *testing.T) {
		f := mfaFixture(t, iam.TwoFactorRequired)
		u := f.user(t)
		token := enrollmentToken(t, f.call(t, "POST", "/password/login", "", map[string]string{"identifier": u.Email, "password": u.Password}))
		f.call(t, "PATCH", "/me", token, map[string]string{"username": "unqualifiedmfa"}).want(t, http.StatusForbidden, "forbidden")
		_, created := f.totp(t, token)
		session := factorSession(t, created, u.ID)
		f.call(t, "PATCH", "/me", session.AccessToken, map[string]string{"preferred_language": "en"}).want(t, http.StatusOK, "")
	})
	t.Run("AK-J07-C02_strong_factors_work_but_email_cannot_elevate_required_MFA", func(t *testing.T) {
		f := mfaFixture(t, iam.TwoFactorOptional)
		u := f.user(t)
		initial := f.signIn(t, u)
		secret, created := f.totp(t, initial.AccessToken)
		factorSession(t, created, u.ID)
		step := f.challenge(t, u)
		tokensFrom(t, f.call(t, "POST", "/2fa/verify", "", map[string]any{"user_id": u.ID, "challenge": step.Challenge, "factor_id": created.Factor.ID, "code": authtest.TOTPCode(t, secret, time.Now().Add(30*time.Second))}), u.ID)
		smsUser := f.user(t)
		smsSession := f.signIn(t, smsUser)
		phone := "+12025550181"
		f.call(t, "POST", "/me/2fa/setup", smsSession.AccessToken, map[string]string{"method": "sms", "phone_number": phone}).want(t, http.StatusOK, "")
		code := f.out.Last(t, iam.MessageVerification, phone).Code
		r := f.call(t, "POST", "/me/2fa/factors", smsSession.AccessToken, map[string]any{"method": "sms", "phone_number": phone, "code": code, "default": true})
		r.want(t, http.StatusCreated, "")
		var sms factorResult
		decode(t, r.body, &sms)
		factorSession(t, sms, smsUser.ID)
		challenge := f.challenge(t, smsUser)
		loginCode := f.out.Last(t, iam.MessageLoginCode, phone).Code
		tokensFrom(t, f.call(t, "POST", "/2fa/verify", "", map[string]any{"user_id": smsUser.ID, "challenge": challenge.Challenge, "factor_id": sms.Factor.ID, "code": loginCode}), smsUser.ID)
		// Legacy optional email-factor support must not be mistaken for the
		// stronger policy applied when this account is promoted.
		weakUser := f.user(t)
		weakSession := f.signIn(t, weakUser)
		f.call(t, "POST", "/me/2fa/setup", weakSession.AccessToken, map[string]string{"method": "email"}).want(t, http.StatusOK, "")
		emailCode := f.out.Last(t, iam.MessageVerification, weakUser.Email).Code
		r = f.call(t, "POST", "/me/2fa/factors", weakSession.AccessToken, map[string]string{"method": "email", "code": emailCode})
		r.want(t, http.StatusCreated, "")
		var email factorResult
		decode(t, r.body, &email)
		weakToken := factorSession(t, email, weakUser.ID)
		required := true
		_, err := f.auth.UpdateUser(t.Context(), iam.SystemIdentity(), weakUser.ID, iam.UserUpdate{MFARequired: &required})
		noError(t, err)
		f.call(t, "PATCH", "/me", weakToken.AccessToken, map[string]string{"username": "emailonlyelevation"}).want(t, http.StatusForbidden, "2fa_enrollment_required")
		enrollmentToken(t, f.call(t, "POST", "/password/login", "", map[string]string{"identifier": weakUser.Email, "password": weakUser.Password}))
	})
	t.Run("AK-J07-C03_wrong_replayed_expired_and_parallel_factor_proofs", func(t *testing.T) {
		f := mfaFixture(t, iam.TwoFactorOptional)
		u := f.user(t)
		_, created := f.totp(t, f.signIn(t, u).AccessToken)
		step := f.challenge(t, u)
		f.call(t, "POST", "/2fa/verify", "", map[string]any{"user_id": u.ID, "challenge": step.Challenge, "factor_id": created.Factor.ID, "code": "not-a-code"}).want(t, http.StatusUnauthorized, "invalid_code")
		body := map[string]any{"user_id": u.ID, "challenge": step.Challenge, "code": created.Backup[0], "backup_code": true}
		results := make([]response, 2)
		errs := make([]error, 2)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range results {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				results[i], errs[i] = f.request(t.Context(), "POST", "/2fa/verify", "", body)
			}()
		}
		close(start)
		wg.Wait()
		success := 0
		for i, r := range results {
			noError(t, errs[i])
			if r.status == http.StatusOK {
				success++
				tokensFrom(t, r, u.ID)
			} else {
				r.want(t, http.StatusUnauthorized, "invalid_code")
			}
		}
		if success != 1 {
			t.Fatalf("parallel one-use proof produced %d sessions", success)
		}
		next := f.challenge(t, u)
		f.call(t, "POST", "/2fa/verify", "", map[string]any{"user_id": u.ID, "challenge": next.Challenge, "code": created.Backup[0], "backup_code": true}).want(t, http.StatusUnauthorized, "invalid_code")
		f.expireProofs(t)
		f.call(t, "POST", "/2fa/verify", "", map[string]any{"user_id": u.ID, "challenge": next.Challenge, "code": created.Backup[1], "backup_code": true}).want(t, http.StatusUnauthorized, "invalid_code")
	})
	t.Run("AK-J07-C04_default_factor_and_required_last_factor_policy", func(t *testing.T) {
		f := mfaFixture(t, iam.TwoFactorRequired)
		u := f.user(t)
		enroll := enrollmentToken(t, f.call(t, "POST", "/password/login", "", map[string]string{"identifier": u.Email, "password": u.Password}))
		_, created := f.totp(t, enroll)
		token := factorSession(t, created, u.ID)
		f.call(t, "PATCH", "/me/2fa/factors/"+created.Factor.ID, token.AccessToken, map[string]bool{"default": true}).want(t, http.StatusOK, "")
		f.call(t, "DELETE", "/me/2fa/factors/"+created.Factor.ID, token.AccessToken, nil).want(t, http.StatusForbidden, "2fa_required_by_policy")
		f.call(t, "DELETE", "/me/2fa", token.AccessToken, nil).want(t, http.StatusForbidden, "2fa_required_by_policy")
		f.call(t, "GET", "/me/security", token.AccessToken, nil).want(t, http.StatusOK, "")
		f.challenge(t, u)
	})
	t.Run("AK-J07-C05_backup_regeneration_retires_the_previous_set", func(t *testing.T) {
		f := mfaFixture(t, iam.TwoFactorOptional)
		u := f.user(t)
		_, created := f.totp(t, f.signIn(t, u).AccessToken)
		token := factorSession(t, created, u.ID)
		r := f.call(t, "POST", "/me/2fa/backup-codes", token.AccessToken, nil)
		r.want(t, http.StatusOK, "")
		var regenerated struct {
			Codes []string `json:"backup_codes"`
		}
		decode(t, r.body, &regenerated)
		if len(regenerated.Codes) == 0 || regenerated.Codes[0] == created.Backup[0] {
			t.Fatal("backup regeneration did not replace its secrets")
		}
		step := f.challenge(t, u)
		f.call(t, "POST", "/2fa/verify", "", map[string]any{"user_id": u.ID, "challenge": step.Challenge, "code": created.Backup[0], "backup_code": true}).want(t, http.StatusUnauthorized, "invalid_code")
		tokensFrom(t, f.call(t, "POST", "/2fa/verify", "", map[string]any{"user_id": u.ID, "challenge": step.Challenge, "code": regenerated.Codes[0], "backup_code": true}), u.ID)
	})
	t.Run("AK-J07-C06_host_recovery_reset_never_grants_password_only_access", func(t *testing.T) {
		f := mfaFixture(t, iam.TwoFactorRequired)
		u := f.user(t)
		enroll := enrollmentToken(t, f.call(t, "POST", "/password/login", "", map[string]string{"identifier": u.Email, "password": u.Password}))
		_, created := f.totp(t, enroll)
		token := factorSession(t, created, u.ID)
		noError(t, f.auth.ResetAccountMFA(t.Context(), u.ID))
		f.call(t, "PATCH", "/me", token.AccessToken, map[string]string{"username": "resetbypass"}).want(t, http.StatusUnauthorized, "session_revoked")
		enrollmentToken(t, f.call(t, "POST", "/password/login", "", map[string]string{"identifier": u.Email, "password": u.Password}))
	})
}
