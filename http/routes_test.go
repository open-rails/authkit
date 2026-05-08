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

func TestAPIRoutesOrgRoutesOnlyInMultiMode(t *testing.T) {
	single := newTestServiceWithOrgMode(t, "single")
	requireNoRoute(t, single.APIRoutes(), http.MethodPost, "/token/org")

	multi := newTestServiceWithOrgMode(t, "multi")
	requireRoute(t, multi.APIRoutes(), http.MethodPost, "/token/org")
	requireRoute(t, multi.APIRoutes(RouteOrganizations), http.MethodGet, "/orgs/{org}/members")
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
