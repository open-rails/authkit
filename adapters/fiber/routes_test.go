package authkitfiber_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	authkitfiber "github.com/open-rails/authkit/adapters/fiber"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testhttp"
	"github.com/stretchr/testify/require"
)

func TestMountNativeAnchorsAndOriginalRequest(t *testing.T) {
	const path = "/identity/password/login?proof=original%2Fbytes"
	const body = "{ \"identifier\" : \"unknown@example.test\", \"password\":\"wrong\" }\n"
	var seenURI, seenBody string
	cfg := testhttp.HTTP()
	cfg.APIPath = "/identity"
	cfg.Wrap = func(_ iam.Route, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				seenURI = r.RequestURI
				raw, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				seenBody = string(raw)
				r.Body = io.NopCloser(strings.NewReader(seenBody))
			}
			next.ServeHTTP(w, r)
		})
	}
	auth := testhttp.Auth(t, cfg)
	app := fiber.New()
	require.NoError(t, authkitfiber.Mount(app, auth))
	app.Use(func(c fiber.Ctx) error { return c.SendStatus(418) })
	routes := auth.Routes()
	actual := 0
	for _, route := range app.GetRoutes(true) {
		if strings.HasPrefix(route.Name, authkitfiber.RouteNamePrefix) {
			actual++
		}
	}
	require.Equal(t, len(routes), actual)
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{http.MethodGet, "/.well-known/jwks.json", http.StatusOK},
		{http.MethodGet, "/identity/.well-known/jwks.json", 418},
		{http.MethodGet, "/identity/me", http.StatusUnauthorized},
		{http.MethodGet, "/host", 418},
		{http.MethodPost, path, http.StatusUnauthorized},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		response, err := app.Test(req)
		require.NoError(t, err)
		raw, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		response.Body.Close()
		require.Equal(t, tc.status, response.StatusCode, string(raw))
	}
	require.Equal(t, path, seenURI)
	require.Equal(t, body, seenBody)
}
