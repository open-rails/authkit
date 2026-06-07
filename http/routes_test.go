package authhttp

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAPIRoutesIncludeRegistrationAvailability(t *testing.T) {
	s := newTestService(t)

	requireRoute(t, s.APIRoutes(RouteRegister), http.MethodGet, "/register/availability")
	requireRoute(t, s.Routes().DefaultAPI(), http.MethodGet, "/register/availability")
}

func TestAPIRoutesGroupSelection(t *testing.T) {
	s := newTestService(t)

	routes := s.Routes().Groups(RouteRegister)
	requireRoute(t, routes, http.MethodPost, "/register")
	requireRoute(t, routes, http.MethodGet, "/register/availability")
	requireNoRoute(t, routes, http.MethodPost, "/token")
}

func TestAPIRoutesIncludePreferredLocaleUserRoute(t *testing.T) {
	s := newTestService(t)

	requireRoute(t, s.APIRoutes(RouteUser), http.MethodPatch, "/user/preferred-locale")
}

func TestAPIRoutesIncludeProviderDiscovery(t *testing.T) {
	s := newTestService(t)

	requireRoute(t, s.APIRoutes(RouteCore), http.MethodGet, "/providers")
	requireRoute(t, s.Routes().DefaultAPI(), http.MethodGet, "/providers")
}

// (issue 60) Tenant routes are always registered under RouteTenants — no
// tenant-mode gate; the host controls exposure by mounting the group.
func TestAPIRoutesTenantRoutesAlwaysRegistered(t *testing.T) {
	s := newTestServiceWithTenantMode(t, "")
	requireRoute(t, s.APIRoutes(), http.MethodPost, "/token/tenant")
	requireRoute(t, s.APIRoutes(RouteTenants), http.MethodGet, "/tenants/{tenant}/members")
}

func TestOIDCBrowserRoutesArePrefixNeutral(t *testing.T) {
	s := newTestService(t)

	routes := s.Routes().OIDCBrowser()
	requireRoute(t, routes, http.MethodGet, "/{provider}/login")
	requireRoute(t, routes, http.MethodGet, "/{provider}/callback")
	requireRoute(t, routes, http.MethodGet, "/{provider}/reauth/callback")
	requireNoRoute(t, routes, http.MethodGet, "/oidc/{provider}/login")
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
