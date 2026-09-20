package authkitgin

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/open-rails/authkit/authhttp"
	"github.com/stretchr/testify/require"
)

func TestMountValidatesConfiguration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	require.Error(t, Mount(nil, nil))
	router := gin.New()
	require.Error(t, Mount(router, nil))
	require.Error(t, Mount(router, nil, authhttp.MountOptions{}, authhttp.MountOptions{}))
	require.Empty(t, router.Routes())
}

func TestMountRegistersNativeRoutesWithCanonicalGuards(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := newTestService(t)
	for _, tc := range []struct {
		name string
		opts authhttp.MountOptions
	}{
		{name: "default"},
		{name: "selected groups and prefix", opts: authhttp.MountOptions{
			APIPrefix: "/identity", Groups: []authhttp.RouteGroup{authhttp.RouteAuth, authhttp.RouteAccount},
			ExcludeRoutes: []authhttp.RouteRef{{Method: http.MethodGet, Path: "/me"}},
		}},
		{name: "root prefix", opts: authhttp.MountOptions{APIPrefix: "/"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			canonical, err := authhttp.NewMount(svc, tc.opts)
			require.NoError(t, err)
			router := gin.New()
			router.GET("/host-before", func(c *gin.Context) { c.String(http.StatusOK, "before") })
			require.NoError(t, Mount(router, svc, tc.opts))
			router.GET("/host-after", func(c *gin.Context) { c.String(http.StatusOK, "after") })
			wantRoutes := map[string]bool{"GET /host-before": true, "GET /host-after": true}
			for _, route := range canonical.Routes() {
				wantRoutes[route.Method+" "+ginPathSyntax(route.Path)] = true
			}
			gotRoutes := make(map[string]bool)
			for _, route := range router.Routes() {
				key := route.Method + " " + route.Path
				require.False(t, gotRoutes[key], "duplicate route %s", key)
				gotRoutes[key] = true
			}
			require.Equal(t, wantRoutes, gotRoutes, "native route registry differs from canonical catalog")
			for _, route := range canonical.Routes() {
				requestPath := fillParams(route.Path)
				probe := func(handler http.Handler) *httptest.ResponseRecorder {
					r := httptest.NewRequest(route.Method, requestPath, strings.NewReader("{}"))
					r.Header.Set("Content-Type", "application/json")
					w := httptest.NewRecorder()
					handler.ServeHTTP(w, r)
					return w
				}
				want, got := probe(canonical), probe(router)
				require.Equalf(t, want.Code, got.Code, "%s %s: %s", route.Method, requestPath, got.Body.String())
				require.Equalf(t, want.Header().Get("Content-Type"), got.Header().Get("Content-Type"), "%s %s", route.Method, requestPath)
			}
			for _, path := range []string{"/host-before", "/host-after"} {
				w := httptest.NewRecorder()
				router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
				require.Equal(t, http.StatusOK, w.Code, path)
			}
		})
	}
}

type mountContextKey struct{}

func TestMountPreservesHostMiddlewareParametersAndCookieGuards(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := newTestService(t)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		if c.GetHeader("X-Host-Deny") == "yes" {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), mountContextKey{}, "host"))
		c.Next()
	})
	require.NoError(t, Mount(router, svc, authhttp.MountOptions{
		APIPrefix: "/identity", RefreshCookie: true,
		Wrap: func(spec authhttp.RouteSpec, handler http.Handler) http.Handler {
			if spec.Path != "/user/providers/{provider}" {
				return handler
			}
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("Set-Cookie", "one=1")
				w.Header().Add("Set-Cookie", "two=2")
				io.WriteString(w, r.PathValue("provider")+":"+r.Context().Value(mountContextKey{}).(string))
			})
		},
	}))
	for _, tc := range []struct {
		name, contentType, origin, deny string
		status                          int
	}{
		{name: "valid", contentType: "application/json", origin: "https://example.com", status: http.StatusOK},
		{name: "non JSON", contentType: "text/plain", origin: "https://example.com", status: http.StatusBadRequest},
		{name: "cross origin", contentType: "application/json", origin: "https://attacker.example", status: http.StatusBadRequest},
		{name: "host middleware abort", contentType: "application/json", origin: "https://example.com", deny: "yes", status: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodDelete, "https://example.com/identity/user/providers/google", strings.NewReader("{}"))
			r.Header.Set("Content-Type", tc.contentType)
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("X-Host-Deny", tc.deny)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			require.Equal(t, tc.status, w.Code, w.Body.String())
			if tc.status == http.StatusOK {
				require.Equal(t, "google:host", w.Body.String())
				require.Equal(t, []string{"one=1", "two=2"}, w.Header().Values("Set-Cookie"))
			}
		})
	}
}

func TestMountLeavesUnmatchedRequestsToGin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := newTestService(t)
	router := gin.New()
	router.HandleMethodNotAllowed = true
	require.NoError(t, Mount(router, svc))
	router.NoRoute(func(c *gin.Context) { c.String(http.StatusNotFound, "host not found") })
	router.NoMethod(func(c *gin.Context) { c.String(http.StatusMethodNotAllowed, "host method") })
	for _, tc := range []struct {
		method, path string
		status       int
		body         string
	}{
		{http.MethodGet, "/unknown", http.StatusNotFound, "host not found"},
		{http.MethodPost, authhttp.JWKSPath, http.StatusMethodNotAllowed, "host method"},
	} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		require.Equal(t, tc.status, w.Code)
		require.Equal(t, tc.body, w.Body.String())
	}
}

func TestMountRejectsGinConflictsBeforeRegistration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := newTestService(t)
	for _, path := range []string{"/api/v1/me", "/api/v1/admin/users/:name", "/api/v1/*rest"} {
		t.Run(path, func(t *testing.T) {
			router := gin.New()
			router.GET(path, func(c *gin.Context) { c.String(http.StatusOK, "host") })
			before := router.Routes()
			err := Mount(router, svc)
			require.ErrorContains(t, err, "ExcludeRoutes")
			after := router.Routes()
			require.Len(t, after, len(before), "conflict partially registered AuthKit")
			require.Equal(t, before[0].Path, after[0].Path)
			require.Equal(t, before[0].Method, after[0].Method)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, strings.ReplaceAll(strings.ReplaceAll(path, ":name", "alice"), "*rest", "anything"), nil))
			require.Equal(t, http.StatusOK, w.Code)
			require.Equal(t, "host", w.Body.String())
		})
	}
	router := gin.New()
	router.GET("/api/v1/me", func(c *gin.Context) { c.String(http.StatusOK, "host profile") })
	require.NoError(t, Mount(router, svc, authhttp.MountOptions{
		ExcludeRoutes: []authhttp.RouteRef{{Method: http.MethodGet, Path: "/me"}},
	}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/me", nil))
	require.Equal(t, "host profile", w.Body.String())
}

func TestMountRejectsUnsupportedPathsBeforeRegistration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := newTestService(t)
	for _, prefix := range []string{"/auth:prefix", "/auth/{rest...}", "/auth//nested", "/auth/../nested"} {
		router := gin.New()
		require.Error(t, Mount(router, svc, authhttp.MountOptions{APIPrefix: prefix}), prefix)
		require.Empty(t, router.Routes(), "unsupported prefix left partial routes")
	}
}

func TestMountRejectsGinMiddlewareLimitBeforeRegistration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := newTestService(t)
	router := gin.New()
	// Gin accepts 62 middleware handlers but rejects the 63rd terminal
	// handler. The scratch engine must include the host's middleware chain.
	middleware := make([]gin.HandlerFunc, 62)
	for i := range middleware {
		middleware[i] = func(c *gin.Context) { c.Next() }
	}
	router.Use(middleware...)
	require.ErrorContains(t, Mount(router, svc), "too many handlers")
	require.Empty(t, router.Routes())
}

func TestGinRoutePath(t *testing.T) {
	for _, tc := range []struct{ httpPath, ginPath string }{
		{"/api/v1/me", "/api/v1/me"},
		{"/.well-known/jwks.json", "/.well-known/jwks.json"},
		{"/api/v1/admin/users/{user_id}", "/api/v1/admin/users/:user_id"},
		{"/groups/{group_id}/members/{member_id}", "/groups/:group_id/members/:member_id"},
	} {
		got, err := ginRoutePath(tc.httpPath)
		require.NoError(t, err)
		require.Equal(t, tc.ginPath, got)
	}
	for _, path := range []string{
		"", "not-rooted", "/", "/subtree/", "/files/{rest...}", "/exact/{$}",
		"/bad/{name", "/bad/name}", "/bad/{x-y}", "/bad/{0name}", "/bad/{}",
		"/literal:parameter", "/wildcard/*", "/escaped%2Fslash", "/a//b", "/a/../b",
	} {
		_, err := ginRoutePath(path)
		require.Error(t, err, path)
	}
}
