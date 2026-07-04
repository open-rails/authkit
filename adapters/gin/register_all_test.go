package authkitgin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// #211: RegisterAll mounts JWKS + OIDC (with the bare /oidc redirect) + the
// default API in one call.
func TestRegisterAll(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := newTestService(t)
	r := gin.New()
	RegisterAll(r, svc)

	do := func(method, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		r.ServeHTTP(w, req)
		return w
	}

	require.Equal(t, http.StatusOK, do(http.MethodGet, "/.well-known/jwks.json").Code)
	require.Equal(t, http.StatusMovedPermanently, do(http.MethodGet, "/oidc").Code)
	// An OIDC browser route is mounted under /oidc (no state/code -> 400, not 404).
	require.Equal(t, http.StatusBadRequest, do(http.MethodGet, "/oidc/google/callback").Code)
	// A default-API public route is mounted at root.
	require.Equal(t, http.StatusOK, do(http.MethodGet, "/auth/capabilities").Code)
}
