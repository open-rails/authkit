package authkitgin

import (
	"context"
	"crypto"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/authhttp"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

// MountHandler mounted once as a gin NoRoute fallback (#250) — no gin-side
// route registration exists anymore. Fallback (not bare gin.WrapH) because
// gin pre-sets 404 on NoRoute: the JWKS assertion below pins that implicit-200
// handlers keep their status; the mount's own 404 must still 404.
func TestMountHandlerViaFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	svc := newTestService(t)

	h, err := authhttp.MountHandler(svc, authhttp.MountOptions{})
	require.NoError(t, err)
	router.NoRoute(Fallback(h))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oidc/google/callback", nil))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), `"code":"invalid_request"`)

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/definitely/not/a/route", nil))
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestUsePropagatesContextAndShortCircuits(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	attachUser := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cl := verify.Claims{UserID: "user-1", Email: "u@example.com"}
			next.ServeHTTP(w, r.WithContext(verify.SetClaims(r.Context(), cl)))
		})
	}
	router.GET("/ok", Use(attachUser), func(c *gin.Context) {
		p, ok := Principal(c)
		require.True(t, ok)
		require.Equal(t, "user-1", p.Subject)
		u, ok := UserClaims(c)
		require.True(t, ok)
		_, _ = c.Writer.Write([]byte(u.UserID))
	})

	stop := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "stop", http.StatusUnauthorized)
		})
	}
	router.GET("/stop", Use(stop), func(c *gin.Context) {
		t.Fatal("handler should not run")
	})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ok", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "user-1", rec.Body.String())

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/stop", nil))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Body.String(), "stop")
}

func newTestService(t *testing.T) *authhttp.Service {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "test-kid")
	require.NoError(t, err)
	cfg := embedded.Config{
		Token: embedded.TokenConfig{
			Issuer:              "https://example.com",
			IssuedAudiences:     []string{"test-app"},
			ExpectedAudiences:   []string{"test-app"},
			AccessTokenDuration: time.Hour,
		},
		Registration: embedded.RegistrationConfig{Verification: embedded.RegistrationVerificationNone},
		Identity: embedded.IdentityConfig{
			Providers: []authprovider.Provider{
				authprovider.Google("google-client", "google-secret"),
			},
		},
		Keys: embedded.KeysConfig{Source: jwtkit.StaticKeySource{
			Active: signer,
			Pubs:   map[string]crypto.PublicKey{"test-kid": signer.PublicKey()},
		}},
	}
	// NewServer requires a non-nil pool (#108). This test only exercises OIDC
	// route mounting + a missing-state/code callback (no DB access), so a
	// lazily-connecting pool (MinConns=0 never dials) is sufficient.
	pool, err := pgxpool.New(context.Background(), "postgres://authkit:authkit@127.0.0.1:5432/authkit_test")
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	client, err := embedded.New(cfg, pool)
	require.NoError(t, err)
	// Rate limiting off: the parity test probes the whole route table twice
	// (old stack + new mount) and must not trip order-dependent 429s.
	svc, err := authhttp.NewServer(client, authhttp.WithoutRateLimiter())
	require.NoError(t, err)
	return svc
}
