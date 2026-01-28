package authhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	core "github.com/PaulFidika/authkit/core"
	jwtkit "github.com/PaulFidika/authkit/jwt"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

type testVerifier struct {
	opts   core.Options
	keyfun func(token *jwt.Token) (any, error)
	accept *core.AcceptConfig
}

func (v testVerifier) JWKS() jwtkit.JWKS                                    { return jwtkit.JWKS{} }
func (v testVerifier) Keyfunc() func(token *jwt.Token) (any, error)         { return v.keyfun }
func (v testVerifier) Options() core.Options                                { return v.opts }
func (v testVerifier) ListRoleSlugsByUser(context.Context, string) []string { return nil }
func (v testVerifier) GetProviderUsername(context.Context, string, string) (string, error) {
	return "", nil
}
func (v testVerifier) AcceptConfig() core.AcceptConfig {
	if v.accept == nil {
		return core.AcceptConfig{}
	}
	return *v.accept
}

func signToken(t *testing.T, signer jwtkit.Signer, claims map[string]any) string {
	t.Helper()
	tok, err := signer.Sign(context.Background(), claims)
	require.NoError(t, err)
	return tok
}

func TestRequired_RequiresExp_ServiceIssued(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)
	pub := signer.PublicKey()

	v := testVerifier{
		opts: core.Options{
			Issuer:            "https://example.com",
			ExpectedAudiences: []string{"test-app"},
		},
		keyfun: func(token *jwt.Token) (any, error) { return pub, nil },
	}

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
	pub := signer.PublicKey()

	v := testVerifier{
		opts: core.Options{
			Issuer:            "https://example.com",
			ExpectedAudiences: []string{"test-app"},
		},
		keyfun: func(token *jwt.Token) (any, error) { return pub, nil },
	}

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
	pub := signer.PublicKey()

	v := testVerifier{
		opts: core.Options{
			Issuer:            "https://example.com",
			ExpectedAudiences: []string{"test-app"},
		},
		keyfun: func(token *jwt.Token) (any, error) { return pub, nil },
	}

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
	require.JSONEq(t, `{"error":"invalid_token"}`, w.Body.String())
}

func TestRequired_RejectsIatInFuture_WhenPresent(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)
	pub := signer.PublicKey()

	v := testVerifier{
		opts: core.Options{
			Issuer:            "https://example.com",
			ExpectedAudiences: []string{"test-app"},
		},
		keyfun: func(token *jwt.Token) (any, error) { return pub, nil },
	}

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
	require.JSONEq(t, `{"error":"invalid_token"}`, w.Body.String())
}

func TestRequired_RequiresExp_VerifyOnlyAcceptConfig(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)
	pub := signer.PublicKey()

	accept := core.AcceptConfig{
		Issuers: []core.IssuerAccept{
			{Issuer: "https://example.com", Audiences: []string{"test-app"}},
		},
		Skew: 60 * time.Second,
	}
	v := testVerifier{
		keyfun: func(token *jwt.Token) (any, error) { return pub, nil },
		accept: &accept,
	}

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
