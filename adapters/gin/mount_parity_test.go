package authkitgin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/open-rails/authkit/authhttp"
	"github.com/stretchr/testify/require"
)

// oldThreeCallRouter is a FROZEN replica of the pre-#250 registration surface
// (RegisterJWKS at root + RegisterOIDC at /oidc + RegisterAPI under /api/v1,
// exactly what doujins/hentai0 shipped). It exists only as the parity fixture:
// the new MountHandler must serve the same (method, path) set with the same
// handlers — and therefore the same gating — as this did.
func oldThreeCallRouter(svc *authhttp.Service) *gin.Engine {
	r := gin.New()
	ginRegister := func(rt gin.IRouter, routes []authhttp.RouteSpec) {
		for _, route := range routes {
			handler := route.Handler
			paramNames := ginParamNames(route.Path)
			rt.Handle(route.Method, ginPathSyntax(route.Path), func(c *gin.Context) {
				for _, name := range paramNames {
					c.Request.SetPathValue(name, c.Param(name))
				}
				handler.ServeHTTP(c.Writer, c.Request)
			})
		}
	}
	r.GET("/.well-known/jwks.json", gin.WrapH(svc.JWKSHandler()))
	oidc := svc.Routes().OIDCBrowser()
	for i := range oidc {
		oidc[i].Path = "/oidc" + oidc[i].Path
	}
	ginRegister(r, oidc)
	ginRegister(r.Group("/api/v1"), svc.Routes().DefaultAPI())
	return r
}

func ginPathSyntax(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			parts[i] = ":" + strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}")
		}
	}
	return strings.Join(parts, "/")
}

func ginParamNames(path string) []string {
	var names []string
	for _, part := range strings.Split(path, "/") {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			names = append(names, strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}"))
		}
	}
	return names
}

// fillParams substitutes {param} segments with a concrete sample value so a
// spec path becomes a requestable URL.
func fillParams(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			parts[i] = "google" // valid for {provider}; arbitrary for the rest
		}
	}
	return strings.Join(parts, "/")
}

// TestMountHandlerParityWithOldRegistration is the #250 security invariant:
// for EVERY route in the registry, an identical unauthenticated request gets
// an identical status from the old three-call gin registration and from the
// new single MountHandler — same route set, same handler, same gate. A route
// the new mount dropped would 404 here while the old stack doesn't; a route
// that lost its gate would 200 where the old stack 401s.
func TestMountHandlerParityWithOldRegistration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := newTestService(t)

	oldR := oldThreeCallRouter(svc)
	newH, err := authhttp.MountHandler(svc, authhttp.MountOptions{})
	require.NoError(t, err)

	probe := func(h http.Handler, method, path string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	type ref struct{ method, path string }
	var table []ref
	for _, rt := range svc.Routes().DefaultAPI() {
		table = append(table, ref{rt.Method, "/api/v1" + rt.Path})
	}
	for _, rt := range svc.Routes().OIDCBrowser() {
		table = append(table, ref{rt.Method, "/oidc" + rt.Path})
	}
	table = append(table, ref{http.MethodGet, "/.well-known/jwks.json"})
	require.Greater(t, len(table), 30, "route registry unexpectedly small — parity fixture broken")

	for _, rt := range table {
		url := fillParams(rt.path)
		oldCode := probe(oldR, rt.method, url)
		newCode := probe(newH, rt.method, url)
		require.NotEqualf(t, http.StatusNotFound, oldCode, "%s %s: old registration misses a registry route (fixture bug)", rt.method, url)
		require.Equalf(t, oldCode, newCode, "%s %s: old=%d new=%d — mount diverged from the three-call registration", rt.method, url, oldCode, newCode)
	}

	// Nothing EXTRA: paths neither stack serves stay 404 on the new mount
	// (no accidental wildcards / prefix bleed).
	for _, rt := range []ref{
		{http.MethodGet, "/api/v1/definitely-not-a-route"},
		{http.MethodPost, "/admin/users"},             // API route without its prefix
		{http.MethodGet, "/api/v1/oidc/google/login"}, // browser route under the API prefix
		{http.MethodGet, "/oidc/google/nope"},
		{http.MethodGet, "/"},
	} {
		require.Equalf(t, http.StatusNotFound, probe(newH, rt.method, rt.path), "%s %s must not be served", rt.method, rt.path)
	}
	// Deliberate divergence from gin: a known path with the wrong method is a
	// spec-correct 405 from net/http ServeMux (gin 404'd). Still not served.
	require.Equal(t, http.StatusMethodNotAllowed, probe(newH, http.MethodPut, "/api/v1/me"))
}

// ExcludeRoutes is the first-class replacement for the host-side hand filter
// (doujins shadows GET /admin/users and GET /me/permissions): the excluded
// (method, path) 404s, siblings and every other route keep serving.
func TestMountHandlerExcludeRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := newTestService(t)

	h, err := authhttp.MountHandler(svc, authhttp.MountOptions{
		ExcludeRoutes: []authhttp.RouteRef{
			{Method: http.MethodGet, Path: "/admin/users"},
			{Method: http.MethodGet, Path: "/me/permissions"},
		},
	})
	require.NoError(t, err)

	probe := func(method, path string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec.Code
	}

	require.Equal(t, http.StatusNotFound, probe(http.MethodGet, "/api/v1/admin/users"))
	// Sibling under the same prefix keeps its (gated) registration.
	require.Equal(t, http.StatusUnauthorized, probe(http.MethodGet, "/api/v1/admin/users/u-1"))
	// Unrelated routes unaffected.
	require.Equal(t, http.StatusUnauthorized, probe(http.MethodGet, "/api/v1/me"))
	require.Equal(t, http.StatusOK, probe(http.MethodGet, "/.well-known/jwks.json"))
}
