package captcha_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit/adapters/captcha"
	"github.com/open-rails/authkit/iam"
)

// A refused token is iam.ErrCaptchaFailed; a provider that cannot judge it
// (a wrong secret, an outage) is another error, so AuthKit fails closed with
// captcha_unavailable instead of blaming the person.
func TestVerifyTellsRefusalsFromFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("sitekey") != "site" {
			http.Error(w, "hCaptcha gets the site key", http.StatusBadRequest)
			return
		}
		switch r.PostForm.Get("response") {
		case "ok":
			fmt.Fprint(w, `{"success":true,"hostname":"shop.example.com"}`)
		case "spent":
			fmt.Fprint(w, `{"success":false,"error-codes":["invalid-or-already-seen-response"]}`)
		case "misconfigured":
			fmt.Fprint(w, `{"success":false,"error-codes":["sitekey-secret-mismatch"]}`)
		default:
			http.Error(w, "down", http.StatusBadGateway)
		}
	}))
	defer server.Close()
	v, err := captcha.New(captcha.Config{Provider: captcha.HCaptcha, SiteKey: "site", Secret: "secret", VerifyURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if w := v.Widget(); w.Provider != "hcaptcha" || w.SiteKey != "site" {
		t.Fatalf("widget %+v", w)
	}
	ctx := t.Context()
	if err := v.Verify(ctx, "ok", "203.0.113.9"); err != nil {
		t.Fatalf("passing token: %v", err)
	}
	if err := v.Verify(ctx, "spent", ""); !errors.Is(err, iam.ErrCaptchaFailed) {
		t.Fatalf("spent token: %v", err)
	}
	for _, token := range []string{"misconfigured", "down"} {
		if err := v.Verify(ctx, token, ""); err == nil || errors.Is(err, iam.ErrCaptchaFailed) {
			t.Fatalf("%s: %v, want a provider failure", token, err)
		}
	}
	if _, err := captcha.New(captcha.Config{Provider: "recaptcha", SiteKey: "s", Secret: "s"}); err == nil {
		t.Fatal("an unknown provider was accepted")
	}
}
