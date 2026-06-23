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
	requireNoRoute(t, routes, http.MethodPost, "/password/login")
}

func TestAPIRoutesIncludePreferredLanguageUserRoute(t *testing.T) {
	s := newTestService(t)

	requireRoute(t, s.APIRoutes(RouteUser), http.MethodPatch, "/user/preferred-language")
	requireNoRoute(t, s.APIRoutes(RouteUser), http.MethodPatch, "/user/preferred-locale")
	requireRoute(t, s.APIRoutes(RouteUser), http.MethodGet, "/me")
	requireNoRoute(t, s.APIRoutes(RouteUser), http.MethodGet, "/user/me")
	requireNoRoute(t, s.APIRoutes(RouteUser), http.MethodGet, "/me/bootstrap")
	requireNoRoute(t, s.APIRoutes(RouteUser), http.MethodGet, "/user/bootstrap")
}

func TestAPIRoutesAdminUserRecoverySurface(t *testing.T) {
	s := newTestService(t)
	routes := s.APIRoutes(RouteAdmin)

	requireRoute(t, routes, http.MethodPost, "/admin/users/{user_id}/recover")
	requireNoRoute(t, routes, http.MethodPost, "/admin/users/set-email")
	requireNoRoute(t, routes, http.MethodPost, "/admin/users/set-username")
	requireNoRoute(t, routes, http.MethodPost, "/admin/users/set-password")
	requireNoRoute(t, routes, http.MethodPost, "/admin/users/toggle-active")
}

func TestPreferredLanguageSupportedSet(t *testing.T) {
	s := &Service{langCfg: &LanguageConfig{Supported: []string{"en", "es"}, Default: "en"}}

	require.True(t, s.supportsLanguage("es"))
	require.False(t, s.supportsLanguage("zh"))
	require.True(t, (&Service{}).supportsLanguage("en"))
	require.False(t, (&Service{}).supportsLanguage("zz"))
}

func TestAPIRoutesRemoveConfirmLinkRoutes(t *testing.T) {
	s := newTestService(t)

	requireNoRoute(t, s.APIRoutes(RouteSession), http.MethodPost, "/email/password/reset/confirm-link")
	requireNoRoute(t, s.APIRoutes(RouteSession), http.MethodPost, "/phone/password/reset/confirm-link")
	requireNoRoute(t, s.APIRoutes(RouteRegister), http.MethodPost, "/email/verify/confirm-link")
	requireNoRoute(t, s.APIRoutes(RouteRegister), http.MethodPost, "/phone/verify/confirm-link")
	requireRoute(t, s.APIRoutes(RouteSession), http.MethodPost, "/email/password/reset/confirm")
	requireRoute(t, s.APIRoutes(RouteSession), http.MethodPost, "/phone/password/reset/confirm")
	requireRoute(t, s.APIRoutes(RouteRegister), http.MethodPost, "/email/verify/confirm")
	requireRoute(t, s.APIRoutes(RouteRegister), http.MethodPost, "/phone/verify/confirm")
}

func TestAPIRoutesCollapseContactChangeRoutes(t *testing.T) {
	s := newTestService(t)
	routes := s.APIRoutes(RouteUser)

	requireRoute(t, routes, http.MethodPost, "/user/email")
	requireRoute(t, routes, http.MethodPost, "/user/phone")
	for _, path := range []string{
		"/user/email/change",
		"/user/email/change/request",
		"/user/email/change/confirm",
		"/user/email/change/resend",
		"/user/email/change/cancel",
		"/user/phone/change",
		"/user/phone/change/request",
		"/user/phone/change/confirm",
		"/user/phone/change/resend",
		"/user/phone/change/cancel",
	} {
		requireNoRoute(t, routes, http.MethodPost, path)
	}
}

func TestAPIRoutesCollapseTwoFactorRoutes(t *testing.T) {
	s := newTestService(t)
	userRoutes := s.APIRoutes(RouteUser)
	sessionRoutes := s.APIRoutes(RouteSession)

	requireRoute(t, userRoutes, http.MethodGet, "/user/2fa")
	requireRoute(t, userRoutes, http.MethodPost, "/user/2fa")
	requireRoute(t, userRoutes, http.MethodDelete, "/user/2fa")
	requireRoute(t, userRoutes, http.MethodPost, "/user/2fa/backup-codes")
	requireRoute(t, sessionRoutes, http.MethodPost, "/2fa/challenge")
	requireRoute(t, sessionRoutes, http.MethodPost, "/2fa/verify")
	requireNoRoute(t, userRoutes, http.MethodPost, "/2fa/verify")
	requireNoRoute(t, sessionRoutes, http.MethodGet, "/user/2fa")
	for _, path := range []string{
		"/user/2fa/start-phone",
		"/user/2fa/enable",
		"/user/2fa/disable",
		"/user/2fa/regenerate-codes",
	} {
		requireNoRoute(t, userRoutes, http.MethodPost, path)
	}
}

func TestAPIRoutesIncludeProviderDiscovery(t *testing.T) {
	s := newTestService(t)

	requireRoute(t, s.APIRoutes(RoutePublic), http.MethodGet, "/identity-providers")
	requireRoute(t, s.Routes().DefaultAPI(), http.MethodGet, "/identity-providers")
	requireNoRoute(t, s.Routes().DefaultAPI(), http.MethodGet, "/providers")
}

func TestAPIRoutesSessionWithoutRegister(t *testing.T) {
	s := newTestService(t)
	routes := s.APIRoutes(RoutePublic, RouteSession, RouteUser)

	requireRoute(t, routes, http.MethodPost, "/password/login")
	requireRoute(t, routes, http.MethodPost, "/token")
	requireRoute(t, routes, http.MethodPost, "/email/password/reset/request")
	requireRoute(t, routes, http.MethodPost, "/2fa/verify")
	requireRoute(t, routes, http.MethodPost, "/solana/login")
	requireRoute(t, routes, http.MethodGet, "/me")
	requireRoute(t, routes, http.MethodPost, "/reauth/password")
	requireNoRoute(t, routes, http.MethodPost, "/register")
	requireNoRoute(t, routes, http.MethodGet, "/register/availability")
	requireNoRoute(t, routes, http.MethodPost, "/email/verify/request")
}

func TestAPIRoutesUserIncludesSelfServiceAuth(t *testing.T) {
	s := newTestService(t)
	routes := s.APIRoutes(RouteUser)

	requireRoute(t, routes, http.MethodPost, "/reauth/password")
	requireRoute(t, routes, http.MethodPost, "/reauth/2fa")
	requireRoute(t, routes, http.MethodPost, "/oidc/{provider}/link/start")
	requireRoute(t, routes, http.MethodPost, "/oidc/{provider}/reauth/start")
	requireRoute(t, routes, http.MethodPost, "/solana/link")
	requireNoRoute(t, routes, http.MethodPost, "/password/login")
	requireNoRoute(t, routes, http.MethodPost, "/solana/login")
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
