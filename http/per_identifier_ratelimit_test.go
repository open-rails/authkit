package authhttp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	core "github.com/open-rails/authkit/core"
)

func newPerIdentifierTestService(t *testing.T) *Service {
	t.Helper()
	cfg := core.Config{
		Token: core.TokenConfig{
			Issuer:            "https://example.com",
			IssuedAudiences:   []string{"test-app"},
			ExpectedAudiences: []string{"test-app"},
		},
		Frontend:     core.FrontendConfig{BaseURL: "https://example.com"},
		Registration: core.RegistrationConfig{Verification: core.RegistrationVerificationNone},
	}
	svc, err := NewServer(cfg, newNoDBPool(t))
	require.NoError(t, err)
	return svc
}

// TestPerIdentifierRateLimit_2FAVerify proves the distributed-brute-force gap is
// closed: many IPs hammering the same user_id exhaust the per-identifier budget
// even though each per-IP budget is untouched.
func TestPerIdentifierRateLimit_2FAVerify(t *testing.T) {
	svc := newPerIdentifierTestService(t)
	h := svc.APIHandler()

	body := `{"user_id":"victim-user","code":"123456","challenge":"bogus"}`
	limit := DefaultRateLimits()[RL2FAVerify].Limit

	for i := 0; i < limit; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/2fa/verify", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		// A fresh IP every attempt: per-IP budget never trips.
		r.RemoteAddr = fmt.Sprintf("203.0.113.%d:1234", i+1)
		h.ServeHTTP(w, r)
		require.NotEqual(t, http.StatusTooManyRequests, w.Code, "attempt %d should not be limited", i+1)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/2fa/verify", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "198.51.100.7:1234"
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusTooManyRequests, w.Code, "per-identifier budget should trip on a fresh IP")
	require.Contains(t, w.Body.String(), `"code":"rate_limited"`)

	// A different user_id from yet another fresh IP is unaffected.
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/2fa/verify", strings.NewReader(`{"user_id":"other-user","code":"123456","challenge":"bogus"}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "198.51.100.8:1234"
	h.ServeHTTP(w, r)
	require.NotEqual(t, http.StatusTooManyRequests, w.Code)
}

// TestPerIdentifierRateLimit_PhoneVerifyConfirm does the same for the 6-digit
// phone verification code keyed by phone number.
func TestPerIdentifierRateLimit_PhoneVerifyConfirm(t *testing.T) {
	svc := newPerIdentifierTestService(t)
	h := svc.APIHandler()

	body := `{"phone_number":"+15555550123","code":"123456"}`
	limit := DefaultRateLimits()[RLPhoneVerifyConfirm].Limit

	for i := 0; i < limit; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/phone/verify/confirm", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = fmt.Sprintf("203.0.113.%d:1234", i+1)
		h.ServeHTTP(w, r)
		require.NotEqual(t, http.StatusTooManyRequests, w.Code, "attempt %d should not be limited", i+1)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/phone/verify/confirm", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "198.51.100.7:1234"
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusTooManyRequests, w.Code)
}
