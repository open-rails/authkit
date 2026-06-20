package authkitgin

import (
	"crypto"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	core "github.com/open-rails/authkit/core"
	authhttp "github.com/open-rails/authkit/http"
	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/stretchr/testify/require"
)

func TestRegisterRoutesSetsPathValues(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	v1 := router.Group("/api/v1")

	RegisterRoutes(v1, []authhttp.RouteSpec{{
		Method: http.MethodGet,
		Path:   "/namespaces/{slug}",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(r.PathValue("slug")))
		}),
	}}, nil)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/cozy", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "cozy", rec.Body.String())
}

func TestRegisterOIDCMountPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	svc := newTestService(t)

	RegisterOIDC(router, svc, "/oidc")

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oidc/google/callback", nil))

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), `"error":"invalid_request"`)
}

func newTestService(t *testing.T) *authhttp.Service {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "test-kid")
	require.NoError(t, err)
	cfg := core.Config{
		Issuer:              "https://example.com",
		IssuedAudiences:     []string{"test-app"},
		ExpectedAudiences:   []string{"test-app"},
		AccessTokenDuration: time.Hour,
		Keys: jwtkit.StaticKeySource{
			Active: signer,
			Pubs:   map[string]crypto.PublicKey{"test-kid": signer.PublicKey()},
		},
	}
	svc, err := authhttp.NewService(cfg)
	require.NoError(t, err)
	return svc
}
