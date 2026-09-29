package authkitgin

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
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
	engine := gin.New()
	require.NoError(t, Mount(engine, auth))
	engine.NoRoute(func(c *gin.Context) { c.Status(418) })
	require.Len(t, engine.Routes(), len(auth.Routes()))
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{http.MethodGet, "/.well-known/jwks.json", http.StatusOK},
		{http.MethodHead, "/.well-known/jwks.json", http.StatusOK},
		{http.MethodGet, "/identity/.well-known/jwks.json", 418},
		{http.MethodGet, "/identity/me", http.StatusUnauthorized},
		{http.MethodGet, "/host", 418},
		{http.MethodPost, path, http.StatusUnauthorized},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		require.Equal(t, tc.status, w.Code, w.Body.String())
	}
	require.Equal(t, path, seenURI)
	require.Equal(t, body, seenBody)
}
