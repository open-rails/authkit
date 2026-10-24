package critical_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

func TestCriticalPasswordAdmission(t *testing.T) {
	f := newFixture(t)
	t.Run("AK-J04-C01_valid_and_invalid_password_admission", func(t *testing.T) {
		u := f.user(t)
		for _, address := range []string{u.Email, "missing-person@example.com"} {
			f.call(t, "POST", "/password/login", "", map[string]string{"identifier": address, "password": "wrong-password"}).want(t, http.StatusUnauthorized, "invalid_credentials")
		}
		live, err := f.auth.Sessions(t.Context(), u.ID)
		noError(t, err)
		if len(live) != 0 {
			t.Fatal("invalid password created a session")
		}
		f.signIn(t, u)
	})
	t.Run("AK-J04-C02_disabled_unverified_and_MFA_required_accounts_do_not_get_ordinary_sessions", func(t *testing.T) {
		u := f.user(t)
		noError(t, f.auth.Ban(t.Context(), iam.SystemIdentity(), u.ID, iam.Ban{}))
		f.call(t, "POST", "/password/login", "", map[string]string{"identifier": u.Email, "password": u.Password}).want(t, http.StatusUnauthorized, "user_banned")
		g := newFixture(t, proofRegistration())
		noError(t, g.auth.Start(context.Background()))
		deleted := g.user(t)
		results, err := g.auth.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{deleted.ID})
		noError(t, err)
		if len(results) != 1 || results[0].Err != nil {
			t.Fatalf("delete: %+v", results)
		}
		g.call(t, "POST", "/password/login", "", map[string]string{"identifier": deleted.Email, "password": deleted.Password}).want(t, http.StatusUnauthorized, "account_disabled")
		unverified, err := g.auth.CreateUser(t.Context(), iam.NewUser{Email: "unverified-login@example.com", Username: "unverifiedlogin", Password: authtest.Password})
		noError(t, err)
		r := g.call(t, "POST", "/password/login", "", map[string]string{"identifier": *unverified.Email, "password": authtest.Password})
		r.want(t, http.StatusOK, "")
		var pending signInResult
		decode(t, r.body, &pending)
		if pending.Status != "verification_required" || pending.Tokens != nil {
			t.Fatalf("unverified login skipped contact proof: %s", r.body)
		}
		m := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			c.TwoFactor.Mode = iam.TwoFactorRequired
			c.TwoFactor.Methods = []iam.TwoFactorMethod{iam.TwoFactorTOTP}
		}))
		required := m.user(t)
		r = m.call(t, "POST", "/password/login", "", map[string]string{"identifier": required.Email, "password": required.Password})
		r.want(t, http.StatusOK, "")
		decode(t, r.body, &pending)
		if pending.Status != "enrollment_required" || pending.Tokens != nil {
			t.Fatalf("required MFA issued an ordinary session: %s", r.body)
		}
	})
	t.Run("AK-J04-C03_new_device_limit_requires_the_delivered_code", func(t *testing.T) {
		g := deviceFixture(t)
		u := g.user(t)
		g.signIn(t, u)
		step, cookie := g.deviceStep(t, u)
		proof := g.out.Last(t, iam.MessageNewDeviceCode, u.Email)
		body := map[string]string{"user_id": u.ID, "challenge": step.Challenge, "code": proof.Code}
		r, err := g.requestHeaders(t.Context(), "POST", "/device-verification/confirm", "", body, http.Header{"Cookie": {cookie}})
		noError(t, err)
		tokensFrom(t, r, u.ID)
	})
	t.Run("AK-J04-C04_device_proof_cannot_move_accounts_expire_or_replay", func(t *testing.T) {
		g := deviceFixture(t)
		u := g.user(t)
		other := g.user(t)
		g.signIn(t, u)
		step, _ := g.deviceStep(t, u)
		proof := g.out.Last(t, iam.MessageNewDeviceCode, u.Email)
		g.call(t, "POST", "/device-verification/confirm", "", map[string]string{"user_id": other.ID, "challenge": step.Challenge, "code": proof.Code}).want(t, http.StatusUnauthorized, "invalid_challenge")
		wrong := "0" + proof.Code[1:]
		if wrong == proof.Code {
			wrong = "1" + proof.Code[1:]
		}
		g.call(t, "POST", "/device-verification/confirm", "", map[string]string{"user_id": u.ID, "challenge": step.Challenge, "code": wrong}).want(t, http.StatusUnauthorized, "invalid_code")
		body := map[string]string{"user_id": u.ID, "challenge": step.Challenge, "code": proof.Code}
		tokensFrom(t, g.call(t, "POST", "/device-verification/confirm", "", body), u.ID)
		g.call(t, "POST", "/device-verification/confirm", "", body).want(t, http.StatusUnauthorized, "invalid_challenge")
		another := g.user(t)
		g.signIn(t, another)
		expired, _ := g.deviceStep(t, another)
		code := g.out.Last(t, iam.MessageNewDeviceCode, another.Email).Code
		g.expireProofs(t)
		g.call(t, "POST", "/device-verification/confirm", "", map[string]string{"user_id": another.ID, "challenge": expired.Challenge, "code": code}).want(t, http.StatusUnauthorized, "invalid_challenge")
	})
	t.Run("AK-J04-C05_IP_and_identifier_budgets_are_enforced", func(t *testing.T) {
		g := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			c.HTTP.RateLimits["password_login"] = authkit.RateLimit{Limit: 1, Window: time.Hour}
		}))
		g.call(t, "POST", "/password/login", "", map[string]string{"identifier": "first@example.com", "password": "bad-password"}).want(t, http.StatusUnauthorized, "invalid_credentials")
		r := g.call(t, "POST", "/password/login", "", map[string]string{"identifier": "different@example.com", "password": "bad-password"})
		r.want(t, http.StatusTooManyRequests, "rate_limited")
		if r.header.Get("Retry-After") == "" {
			t.Fatal("rate refusal omitted Retry-After")
		}
		// The public registration send has an additional identifier budget;
		// trusted distinct source addresses must not buy unlimited email sends.
		h := newFixture(t, proofRegistration(), authtest.WithConfig(func(c *authkit.Config) {
			c.HTTP.DirectPeerIP = false
			c.HTTP.TrustedProxies = []string{"127.0.0.0/8"}
			c.HTTP.RateLimits["register_create"] = authkit.RateLimit{Limit: 1, Window: time.Hour}
		}))
		body := map[string]string{"identifier": "budgeted@example.com", "username": "budgetedperson", "password": authtest.Password}
		a, err := h.requestHeaders(t.Context(), "POST", "/register", "", body, http.Header{"X-Forwarded-For": {"192.0.2.10"}})
		noError(t, err)
		a.want(t, http.StatusAccepted, "")
		b, err := h.requestHeaders(t.Context(), "POST", "/register", "", body, http.Header{"X-Forwarded-For": {"192.0.2.11"}})
		noError(t, err)
		b.want(t, http.StatusTooManyRequests, "rate_limited")
		if len(h.out.Messages(iam.MessageVerification, "budgeted@example.com")) != 1 {
			t.Fatal("identifier budget allowed duplicate external delivery")
		}
	})
}

type deviceStep struct {
	UserID    string `json:"user_id"`
	Challenge string `json:"challenge"`
}

func deviceFixture(t *testing.T) *fixture {
	return newFixture(t, authtest.WithConfig(func(c *authkit.Config) { c.SignIn.NewDevicesPerAccount = 1 }))
}
func (f *fixture) deviceStep(t *testing.T, u authtest.User) (deviceStep, string) {
	t.Helper()
	// A cookieless native client is deliberately recognized by its address.
	// Obtain a fresh server-issued device cookie for a distinct browser, then
	// present it with this account's password. The cookie itself grants nothing.
	probe := f.call(t, "POST", "/password/login", "", map[string]string{"identifier": "new-browser-probe@example.com", "password": "invalid-password"})
	probe.want(t, http.StatusUnauthorized, "invalid_credentials")
	var sentCookies []string
	for _, cookie := range (&http.Response{Header: probe.header}).Cookies() {
		if cookie.Value != "" && cookie.MaxAge >= 0 {
			sentCookies = append(sentCookies, cookie.Name+"="+cookie.Value)
		}
	}
	cookie := strings.Join(sentCookies, "; ")
	if cookie == "" {
		t.Fatal("server did not issue the new device's opaque cookie")
	}
	r, err := f.requestHeaders(t.Context(), "POST", "/password/login", "", map[string]string{"identifier": u.Email, "password": u.Password}, http.Header{"Cookie": {cookie}})
	noError(t, err)
	r.want(t, http.StatusOK, "")
	var result struct {
		Status string        `json:"status"`
		Tokens *iam.TokenSet `json:"token_set"`
		Step   deviceStep    `json:"device_verification"`
	}
	decode(t, r.body, &result)
	if result.Status != "device_verification_required" || result.Tokens != nil || result.Step.UserID != u.ID || result.Step.Challenge == "" {
		t.Fatalf("new-device proof was bypassed: %s", r.body)
	}
	return result.Step, cookie
}
