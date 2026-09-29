package authkitfiber_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	authkitfiber "github.com/open-rails/authkit/adapters/fiber"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testhttp"
	"github.com/stretchr/testify/require"
)

// The issuer's path roots every native route: JWKS and the API answer beneath
// it, nothing answers at the root, and OIDC redirects to the mounted callback.
func TestMountUnderIssuerBasePath(t *testing.T) {
	auth := testhttp.AuthAt(t, "https://example.com/auth", testhttp.HTTP())
	app := fiber.New()
	require.NoError(t, authkitfiber.Mount(app, auth))
	var mounted int
	for _, route := range app.GetRoutes() {
		if strings.HasPrefix(route.Name, authkitfiber.RouteNamePrefix) {
			mounted++
			require.Truef(t, strings.HasPrefix(route.Path, "/auth/"), "%s %s escapes /auth", route.Method, route.Path)
		}
	}
	require.Equal(t, len(auth.Routes()), mounted)
	for _, path := range []string{"/auth" + iam.JWKSPath, "/auth/api/v1/capabilities"} {
		status, _, body := request(t, app, http.MethodGet, path, "")
		require.Equal(t, http.StatusOK, status, "%s: %s", path, body)
	}
	for _, path := range []string{iam.JWKSPath, "/api/v1/capabilities", "/oidc/github/login"} {
		status, _, _ := request(t, app, http.MethodGet, path, "")
		require.Equal(t, http.StatusNotFound, status, path)
	}
	status, header, body := request(t, app, http.MethodGet, "/auth/oidc/github/login", "")
	require.Equal(t, http.StatusFound, status, body)
	location, err := url.Parse(header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "https://example.com/auth/oidc/github/callback", location.Query().Get("redirect_uri"))
}
