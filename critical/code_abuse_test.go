package critical_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/adapters/captcha"
	"github.com/open-rails/authkit/adapters/twilio"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
)

// TestCriticalCodeAbuse covers what keeps bots and SMS pumping off the code
// starts: a captcha, numbers no person texts from, and budgets of
// unconfirmed texts per number range and per requesting client.
func TestCriticalCodeAbuse(t *testing.T) {
	t.Run("AK-J33-C10_a_code_start_or_sign_up_without_a_passing_captcha_sends_nothing", func(t *testing.T) {
		var mu sync.Mutex
		var seen []url.Values
		siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			mu.Lock()
			seen = append(seen, r.PostForm)
			mu.Unlock()
			switch r.PostForm.Get("response") {
			case "pass":
				fmt.Fprint(w, `{"success":true,"hostname":"shop.example.com"}`)
			case "elsewhere":
				fmt.Fprint(w, `{"success":true,"hostname":"evil.example.net"}`)
			case "down":
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
			default:
				fmt.Fprint(w, `{"success":false,"error-codes":["timeout-or-duplicate"]}`)
			}
		}))
		t.Cleanup(siteverify.Close)
		v, err := captcha.New(captcha.Config{Provider: captcha.Turnstile, SiteKey: "site-key", Secret: "site-secret",
			VerifyURL: siteverify.URL, Hostnames: []string{"shop.example.com"}})
		noError(t, err)
		f := newFixture(t, authtest.WithDeps(func(d *authkit.Deps) { d.Captcha = v }), authtest.WithConfig(func(c *authkit.Config) {
		}))

		var caps struct {
			Captcha *iam.CaptchaWidget `json:"captcha"`
		}
		r := f.call(t, "GET", "/capabilities", "", nil)
		r.want(t, http.StatusOK, "")
		decode(t, r.body, &caps)
		if caps.Captcha == nil || caps.Captcha.Provider != "turnstile" || caps.Captcha.SiteKey != "site-key" {
			t.Fatalf("capabilities name no captcha widget: %s", r.body)
		}

		const address = "captcha-buyer@example.com"
		start := func(token string) response {
			body := map[string]string{"identifier": address, "mode": "code"}
			if token != "" {
				body["captcha_token"] = token
			}
			return f.call(t, "POST", "/passwordless/start", "", body)
		}
		start("").want(t, http.StatusBadRequest, "captcha_failed")
		start("spent").want(t, http.StatusBadRequest, "captcha_failed")
		start("elsewhere").want(t, http.StatusBadRequest, "captcha_failed")
		start("down").want(t, http.StatusServiceUnavailable, "captcha_unavailable")
		if got := len(f.out.Messages("", address)); got != 0 {
			t.Fatalf("a start without a passing captcha sent %d messages", got)
		}
		challenge := challengeOf(t, start("pass"))
		f.confirmCode(t, "/passwordless/confirm", "", codeProof{f.out.Last(t, iam.MessageVerification, address), challenge}).want(t, http.StatusOK, "")

		register := func(token string) response {
			return f.call(t, "POST", "/register", "", map[string]string{"identifier": "captcha-signup@example.com",
				"username": "captchasignup", "password": "a long enough password 7", "captcha_token": token})
		}
		register("spent").want(t, http.StatusBadRequest, "captcha_failed")
		if got := len(f.out.Messages("", "captcha-signup@example.com")); got != 0 {
			t.Fatalf("a sign-up without a passing captcha sent %d messages", got)
		}
		if r := register("pass"); r.status != http.StatusAccepted && r.status != http.StatusOK {
			t.Fatalf("a sign-up with a passing captcha: HTTP %d: %s", r.status, r.body)
		}

		mu.Lock()
		defer mu.Unlock()
		for _, form := range seen {
			if form.Get("secret") != "site-secret" || form.Get("remoteip") == "" {
				t.Fatalf("siteverify got secret %q and remoteip %q", form.Get("secret"), form.Get("remoteip"))
			}
		}
	})

	t.Run("AK-J33-C11_numbers_no_person_texts_from_and_numbers_the_provider_refuses_are_phone_number_not_allowed", func(t *testing.T) {
		f := newFixture(t)
		for number, reason := range map[string]string{
			"+449012345678": "premium_rate",
			"+18002345678":  "toll_free",
			"+447012345678": "personal_number",
			"+33884012345":  "shared_cost",
		} {
			r := f.call(t, "POST", "/passwordless/start", "", map[string]string{"identifier": number, "mode": "code"})
			r.want(t, http.StatusBadRequest, "phone_number_not_allowed")
			if got := refusalReason(t, r); got != reason {
				t.Fatalf("%s refused for %q, want %q", number, got, reason)
			}
			if got := len(f.out.Messages("", number)); got != 0 {
				t.Fatalf("%s was texted %d times", number, got)
			}
		}

		// Twilio's own refusals, through the real adapter: Geo Permissions at
		// create, SMS Pumping Protection as the delivery error.
		api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.Method == http.MethodPost:
				_ = r.ParseForm()
				if r.PostForm.Get("To") == "+12025550190" {
					w.WriteHeader(http.StatusBadRequest)
					fmt.Fprint(w, `{"code":21408,"message":"Permission to send an SMS has not been enabled for the region"}`)
					return
				}
				w.WriteHeader(http.StatusCreated)
				fmt.Fprint(w, `{"sid":"SMpumped","status":"queued"}`)
			default:
				fmt.Fprint(w, `{"sid":"SMpumped","status":"failed","error_code":30450,"error_message":"Message delivery blocked"}`)
			}
		}))
		t.Cleanup(api.Close)
		client := api.Client()
		inner := client.Transport
		client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
			r = r.Clone(r.Context())
			r.URL.Host, r.Host = strings.TrimPrefix(api.URL, "https://"), ""
			return inner.RoundTrip(r)
		})
		sms, err := twilio.NewSMS(twilio.SMSConfig{AccountSID: "ACtest", AuthToken: "token", MessagingServiceSID: "MGtest",
			Client: client, DeliveryPollInterval: 10 * time.Millisecond})
		noError(t, err)
		g := newFixture(t, authtest.WithDeps(func(d *authkit.Deps) { d.SMS = sendOnly{sms} }), authtest.WithConfig(func(c *authkit.Config) {
		}))
		for number, reason := range map[string]string{"+12025550190": "region_not_enabled", "+12025550191": "provider_blocked"} {
			r := g.call(t, "POST", "/passwordless/start", "", map[string]string{"identifier": number, "mode": "code"})
			r.want(t, http.StatusBadRequest, "phone_number_not_allowed")
			if got := refusalReason(t, r); got != reason {
				t.Fatalf("%s refused for %q, want %q", number, got, reason)
			}
		}
		if !g.auth.SMSAvailable() {
			t.Fatal("a refused number closed text messages")
		}
	})

	t.Run("AK-J33-C12_unconfirmed_texts_per_number_range_and_per_client_are_capped_and_a_proven_code_gives_its_text_back", func(t *testing.T) {
		f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			config.Tune(c, func(tn *config.Tuning) { tn.RateLimits["sms_range"] = config.RateLimit{Limit: 2, Window: time.Hour} })
		}))
		start := func(number string) response {
			return f.call(t, "POST", "/passwordless/start", "", map[string]string{"identifier": number, "mode": "code"})
		}
		// Three numbers of one block of 10,000: the third is one too many.
		first := challengeOf(t, start("+12025550170"))
		challengeOf(t, start("+12025550171"))
		start("+12025550172").want(t, http.StatusTooManyRequests, "rate_limited")
		if got := len(f.out.Messages("", "+12025550172")); got != 0 {
			t.Fatalf("a text past its range's budget went out: %d", got)
		}
		// Another block is untouched.
		challengeOf(t, start("+12025560170"))
		// A proven code gives its text back.
		f.confirmCode(t, "/passwordless/confirm", "", codeProof{f.out.Last(t, iam.MessageVerification, "+12025550170"), first}).want(t, http.StatusOK, "")
		challengeOf(t, start("+12025550172"))

		g := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			config.Tune(c, func(tn *config.Tuning) { tn.RateLimits["sms_client"] = config.RateLimit{Limit: 2, Window: time.Hour} })
		}), authtest.WithDeps(func(d *authkit.Deps) {
			d.RequestClient = func(r *http.Request) string { return r.Header.Get("X-Checkout-Merchant") }
		}))
		through := func(merchant, number string) response {
			r, err := g.requestHeaders(t.Context(), "POST", "/passwordless/start", "", map[string]string{"identifier": number, "mode": "code"},
				http.Header{"X-Checkout-Merchant": {merchant}})
			noError(t, err)
			return r
		}
		mine := challengeOf(t, through("merchant-a", "+12025570170"))
		challengeOf(t, through("merchant-a", "+12025580170"))
		through("merchant-a", "+12025590170").want(t, http.StatusTooManyRequests, "rate_limited")
		challengeOf(t, through("merchant-b", "+12025590170"))
		challengeOf(t, through("", "+12025600170"))
		g.confirmCode(t, "/passwordless/confirm", "", codeProof{g.out.Last(t, iam.MessageVerification, "+12025570170"), mine}).want(t, http.StatusOK, "")
		challengeOf(t, through("merchant-a", "+12025610170"))
	})
}

// refusalReason is a refusal's metadata.reason.
func refusalReason(t *testing.T, r response) string {
	t.Helper()
	var env iam.ErrorEnvelope
	decode(t, r.body, &env)
	reason, _ := env.Error.Metadata["reason"].(string)
	return reason
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// sendOnly is a real sender whose health checks pass, so a test drives only
// its sends.
type sendOnly struct{ authkit.SMSSender }

func (sendOnly) CheckHealth(context.Context) error { return nil }
