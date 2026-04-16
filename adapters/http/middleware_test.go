package authhttp

import (
	"context"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	core "github.com/open-rails/authkit/core"
	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/stretchr/testify/require"
)

func signToken(t *testing.T, signer jwtkit.Signer, claims map[string]any) string {
	t.Helper()
	tok, err := signer.Sign(context.Background(), claims)
	require.NoError(t, err)
	return tok
}

func newTestVerifier(t *testing.T, signer *jwtkit.RSASigner, issuer string, audiences []string, opts ...VerifierOption) *Verifier {
	t.Helper()
	v := NewVerifier(opts...)
	err := v.AddIssuer(issuer, audiences, IssuerOptions{
		RawKeys: map[string]*rsa.PublicKey{
			signer.KID(): signer.PublicKey(),
		},
	})
	require.NoError(t, err)
	return v
}

func TestRequired_RequiresExp_ServiceIssued(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)

	v := newTestVerifier(t, signer, "https://example.com", []string{"test-app"})

	protected := Required(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	token := signToken(t, signer, map[string]any{
		"iss": "https://example.com",
		"sub": "user",
		"aud": "test-app",
		"iat": time.Now().Unix(),
		// exp omitted on purpose
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	protected.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.JSONEq(t, `{"error":"missing_exp"}`, w.Body.String())
}

func TestRequired_RejectsExpired_ServiceIssued(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)

	v := newTestVerifier(t, signer, "https://example.com", []string{"test-app"},
		WithSkew(time.Second))

	protected := Required(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	token := signToken(t, signer, map[string]any{
		"iss": "https://example.com",
		"sub": "user",
		"aud": "test-app",
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	protected.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.JSONEq(t, `{"error":"token_expired"}`, w.Body.String())
}

func TestRequired_RejectsNbfInFuture_WhenPresent(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)

	v := newTestVerifier(t, signer, "https://example.com", []string{"test-app"})

	protected := Required(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	token := signToken(t, signer, map[string]any{
		"iss": "https://example.com",
		"sub": "user",
		"aud": "test-app",
		"iat": time.Now().Unix(),
		"nbf": time.Now().Add(30 * time.Minute).Unix(),
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	protected.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.JSONEq(t, `{"error":"token_not_yet_valid"}`, w.Body.String())
}

func TestRequired_RejectsIatInFuture_WhenPresent(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)

	v := newTestVerifier(t, signer, "https://example.com", []string{"test-app"})

	protected := Required(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	token := signToken(t, signer, map[string]any{
		"iss": "https://example.com",
		"sub": "user",
		"aud": "test-app",
		"iat": time.Now().Add(30 * time.Minute).Unix(),
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	protected.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.JSONEq(t, `{"error":"token_not_yet_valid"}`, w.Body.String())
}

func TestRequired_RequiresExp_VerifyOnly(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)

	v := newTestVerifier(t, signer, "https://example.com", []string{"test-app"},
		WithSkew(60*time.Second))

	protected := Required(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	token := signToken(t, signer, map[string]any{
		"iss": "https://example.com",
		"sub": "user",
		"aud": "test-app",
		"iat": time.Now().Unix(),
		// exp omitted on purpose
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	protected.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.JSONEq(t, `{"error":"missing_exp"}`, w.Body.String())
}

func TestRateLimiting_DefaultsEnabledAndOptOutWorks(t *testing.T) {
	cfg := core.Config{
		Issuer:            "https://example.com",
		IssuedAudiences:   []string{"test-app"},
		ExpectedAudiences: []string{"test-app"},
		BaseURL:           "https://example.com",
	}
	svc, err := NewService(cfg)
	require.NoError(t, err)

	h := svc.APIHandler()

	for i := 0; i < 20; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/auth/password/login", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "203.0.113.10:1234"
		h.ServeHTTP(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
	}

	{
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/auth/password/login", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "203.0.113.10:1234"
		h.ServeHTTP(w, r)
		require.Equal(t, http.StatusTooManyRequests, w.Code)
		require.JSONEq(t, `{"error":"rate_limited"}`, w.Body.String())
	}

	// Opt-out: disabling limiter should never rate limit.
	svc = svc.DisableRateLimiter()
	h = svc.APIHandler()
	for i := 0; i < 50; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/auth/password/login", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "203.0.113.10:1234"
		h.ServeHTTP(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
	}

	// Proxy-safe behavior by default: private RemoteAddr returns "" => rate limiting fails open.
	svc, err = NewService(cfg)
	require.NoError(t, err)
	h = svc.APIHandler()
	for i := 0; i < 50; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/auth/password/login", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "10.0.0.10:1234"
		r.Header.Set("X-Forwarded-For", "203.0.113.99")
		h.ServeHTTP(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
	}

	// When behind a trusted proxy, accept forwarded headers and enforce limits on the client IP.
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	svc = svc.WithClientIPFunc(ClientIPFromForwardedHeaders(trusted))
	h = svc.APIHandler()
	for i := 0; i < 20; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/auth/password/login", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "10.0.0.10:1234"
		r.Header.Set("X-Forwarded-For", "203.0.113.99")
		h.ServeHTTP(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/password/login", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "10.0.0.10:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.99")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	require.JSONEq(t, `{"error":"rate_limited"}`, w.Body.String())
}
