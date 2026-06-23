package authhttp

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAPIRoutesGroupContract(t *testing.T) {
	s := newTestService(t)

	register := s.APIRoutes(RouteRegister)
	requireRoute(t, register, http.MethodPost, "/register")
	requireRoute(t, register, http.MethodGet, "/register/availability")
	requireNoRoute(t, register, http.MethodPost, "/token")

	sessionUser := s.APIRoutes(RouteSession, RouteUser)
	requireRoute(t, sessionUser, http.MethodPost, "/password/login")
	requireRoute(t, sessionUser, http.MethodPost, "/token")
	requireRoute(t, sessionUser, http.MethodPost, "/2fa/verify")
	requireRoute(t, sessionUser, http.MethodGet, "/me")
	requireRoute(t, sessionUser, http.MethodPost, "/reauth/password")
	requireRoute(t, sessionUser, http.MethodPost, "/reauth/2fa")
	requireRoute(t, sessionUser, http.MethodPost, "/oidc/{provider}/link/start")
	requireRoute(t, sessionUser, http.MethodPost, "/oidc/{provider}/reauth/start")
	requireNoRoute(t, sessionUser, http.MethodPost, "/register")
	requireNoRoute(t, sessionUser, http.MethodGet, "/user/me")
	requireNoRoute(t, sessionUser, http.MethodGet, "/me/bootstrap")

	admin := s.APIRoutes(RouteAdmin)
	requireRoute(t, admin, http.MethodPost, "/admin/users/{user_id}/recover")
	requireNoRoute(t, admin, http.MethodPost, "/admin/users/toggle-active")

	permissions := s.APIRoutes(RoutePermissionGroups)
	requireRoute(t, permissions, http.MethodPost, "/root/{resource_id}/members")
	requireRoute(t, permissions, http.MethodGet, "/me/groups")
	requireNoRoute(t, permissions, http.MethodPost, "/password/login")

	requireRoute(t, s.Routes().DefaultAPI(), http.MethodGet, "/identity-providers")
	requireNoRoute(t, s.Routes().DefaultAPI(), http.MethodGet, "/providers")
}

func TestOIDCBrowserRoutesArePrefixNeutral(t *testing.T) {
	s := newTestService(t)

	routes := s.Routes().OIDCBrowser()
	requireRoute(t, routes, http.MethodGet, "/{provider}/login")
	requireRoute(t, routes, http.MethodGet, "/{provider}/callback")
	requireRoute(t, routes, http.MethodGet, "/{provider}/reauth/callback")
	requireNoRoute(t, routes, http.MethodGet, "/oidc/{provider}/login")
	requireNoRoute(t, s.APIRoutes(RoutePublic, RouteSession, RouteUser), http.MethodGet, "/{provider}/login")
}

func TestPreferredLanguageSupportedSet(t *testing.T) {
	s := &Service{langCfg: &LanguageConfig{Supported: []string{"en", "es"}, Default: "en"}}

	require.True(t, s.supportsLanguage("es"))
	require.False(t, s.supportsLanguage("zh"))
	require.True(t, (&Service{}).supportsLanguage("en"))
	require.False(t, (&Service{}).supportsLanguage("zz"))
}

func requireRoute(t *testing.T, routes []RouteSpec, method, path string) {
	t.Helper()
	for _, route := range routes {
		if route.Method == method && route.Path == path {
			require.NotNil(t, route.Handler)
			return
		}
	}
	t.Fatalf("route %s %s not found", method, path)
}

func requireNoRoute(t *testing.T, routes []RouteSpec, method, path string) {
	t.Helper()
	for _, route := range routes {
		if route.Method == method && route.Path == path {
			t.Fatalf("route %s %s unexpectedly found", method, path)
		}
	}
}
