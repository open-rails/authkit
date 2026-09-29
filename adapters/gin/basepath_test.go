package authkitgin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testhttp"
	"github.com/stretchr/testify/require"
)

// The issuer's path roots every native route: JWKS and the API answer beneath
// it, nothing answers at the root, and OIDC redirects to the mounted callback.
func TestMountUnderIssuerBasePath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth := testhttp.AuthAt(t, "https://example.com/auth", testhttp.HTTP())
	router := gin.New()
	require.NoError(t, Mount(router, auth))
	router.NoRoute(func(c *gin.Context) { c.Status(http.StatusTeapot) })
	require.Len(t, router.Routes(), len(auth.Routes()))
	for _, route := range router.Routes() {
		require.Truef(t, strings.HasPrefix(route.Path, "/auth/"), "%s %s escapes /auth", route.Method, route.Path)
	}
	serve := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w
	}
	for _, path := range []string{"/auth" + iam.JWKSPath, "/auth/api/v1/capabilities"} {
		require.Equal(t, http.StatusOK, serve(path).Code, path)
	}
	for _, path := range []string{iam.JWKSPath, "/api/v1/capabilities", "/oidc/github/login"} {
		require.Equal(t, http.StatusTeapot, serve(path).Code, path)
	}
	login := serve("/auth/oidc/github/login")
	require.Equal(t, http.StatusFound, login.Code, login.Body.String())
	location, err := url.Parse(login.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "https://example.com/auth/oidc/github/callback", location.Query().Get("redirect_uri"))
}
