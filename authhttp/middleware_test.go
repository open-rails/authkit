package authhttp

import (
	"context"
	"crypto"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/stretchr/testify/require"
)

func signToken(t *testing.T, signer jwtkit.Signer, claims map[string]any) string {
	t.Helper()
	hs, ok := signer.(jwtkit.HeaderSigner)
	require.True(t, ok, "test signer must support JOSE headers")
	tok, err := hs.SignWithHeaders(context.Background(), claims, map[string]any{"typ": AccessTokenType})
	require.NoError(t, err)
	return tok
}

func newTestVerifier(t *testing.T, signer *jwtkit.RSASigner, issuer string, audiences []string, opts ...VerifierOption) *Verifier {
	t.Helper()
	v := NewVerifier(opts...)
	err := v.AddIssuer(issuer, audiences, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{
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
	requireErrorCode(t, w.Body.String(), "missing_exp")
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
	requireErrorCode(t, w.Body.String(), "token_expired")
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
	requireErrorCode(t, w.Body.String(), "token_not_yet_valid")
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
	requireErrorCode(t, w.Body.String(), "token_not_yet_valid")
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
	requireErrorCode(t, w.Body.String(), "missing_exp")
}

func TestRateLimiting_DefaultsEnabledAndOptOutWorks(t *testing.T) {
	cfg := embedded.Config{
		Keys: embedded.KeysConfig{AllowEphemeralDevKeys: true}, // #231: tests opt in explicitly
		Token: embedded.TokenConfig{
			Issuer:            "https://example.com",
			IssuedAudiences:   []string{"test-app"},
			ExpectedAudiences: []string{"test-app"},
		},
		Frontend:     embedded.FrontendConfig{BaseURL: "https://example.com"},
		Registration: embedded.RegistrationConfig{Verification: embedded.RegistrationVerificationNone},
	}
	svc, err := NewServer(newServerClient(t, cfg, newNoDBPool(t)))
	require.NoError(t, err)

	h := svc.APIHandler()

	for i := 0; i < 20; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/password/login", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "203.0.113.10:1234"
		h.ServeHTTP(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
	}

	{
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/password/login", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "203.0.113.10:1234"
		h.ServeHTTP(w, r)
		require.Equal(t, http.StatusTooManyRequests, w.Code)
		require.NotEmpty(t, w.Header().Get("Retry-After"))
		require.Contains(t, w.Body.String(), `"code":"rate_limited"`)
		require.Contains(t, w.Body.String(), `"retry_after_seconds"`)
	}

	// Opt-out: disabling limiter should never rate limit.
	svc, err = NewServer(newServerClient(t, cfg, newNoDBPool(t)), WithoutRateLimiter())
	require.NoError(t, err)
	h = svc.APIHandler()
	for i := 0; i < 50; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/password/login", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "203.0.113.10:1234"
		h.ServeHTTP(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
	}

	// Private Docker/proxy peers are rate-limited by default instead of failing open.
	svc, err = NewServer(newServerClient(t, cfg, newNoDBPool(t)))
	require.NoError(t, err)
	h = svc.APIHandler()
	for i := 0; i < 20; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/password/login", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "10.0.0.10:1234"
		r.Header.Set("X-Forwarded-For", "203.0.113.99")
		h.ServeHTTP(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
	}
	{
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/password/login", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "10.0.0.10:1234"
		r.Header.Set("X-Forwarded-For", "203.0.113.99")
		h.ServeHTTP(w, r)
		require.Equal(t, http.StatusTooManyRequests, w.Code)
		require.Contains(t, w.Body.String(), `"code":"rate_limited"`)
	}

	// Spoofed forwarded headers from untrusted peers are ignored; the peer identity is used.
	svc, err = NewServer(newServerClient(t, cfg, newNoDBPool(t)))
	require.NoError(t, err)
	h = svc.APIHandler()
	for i := 0; i < 20; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/password/login", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "10.0.0.11:1234"
		r.Header.Set("X-Forwarded-For", "203.0.113."+strconv.Itoa(i+1))
		h.ServeHTTP(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
	}
	{
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/password/login", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "10.0.0.11:1234"
		r.Header.Set("X-Forwarded-For", "203.0.113.250")
		h.ServeHTTP(w, r)
		require.Equal(t, http.StatusTooManyRequests, w.Code)
	}

	// When behind a trusted proxy, accept forwarded headers and enforce limits on the client IP.
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	svc, err = NewServer(newServerClient(t, cfg, newNoDBPool(t)), WithClientIPFunc(ClientIPFromForwardedHeaders(trusted)))
	require.NoError(t, err)
	h = svc.APIHandler()
	for i := 0; i < 20; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/password/login", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "10.0.0.10:1234"
		r.Header.Set("X-Forwarded-For", "203.0.113.99")
		h.ServeHTTP(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/password/login", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "10.0.0.10:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.99")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	require.NotEmpty(t, w.Header().Get("Retry-After"))
	require.Contains(t, w.Body.String(), `"code":"rate_limited"`)
	require.Contains(t, w.Body.String(), `"retry_after_seconds"`)
}
