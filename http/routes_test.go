package authhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/stretchr/testify/require"
)

func TestAPIRoutesGroupContract(t *testing.T) {
	s := newRouteFeatureTestService(t, func(cfg *authcore.Config) {
		cfg.Registration.PasswordlessLogin = true
		cfg.SolanaNetwork = "devnet"
	})
	enableTestOIDCProvider(s)

	register := s.APIRoutes(RouteRegistration)
	requireRoute(t, register, http.MethodPost, "/register")
	requireRoute(t, register, http.MethodGet, "/register/availability")
	requireNoRoute(t, register, http.MethodPost, "/email/verify/request")
	requireNoRoute(t, register, http.MethodPost, "/token")

	sessionUser := s.APIRoutes(RouteAuth, RouteAccount)
	requireRoute(t, sessionUser, http.MethodPost, "/password/login")
	requireRoute(t, sessionUser, http.MethodPost, "/passwordless/start")
	requireRoute(t, sessionUser, http.MethodPost, "/passwordless/confirm")
	requireRoute(t, sessionUser, http.MethodPost, "/token")
	requireRoute(t, sessionUser, http.MethodPost, "/2fa/verify")
	requireRoute(t, sessionUser, http.MethodGet, "/me")
	requireRoute(t, sessionUser, http.MethodPost, "/step-up/password")
	requireRoute(t, sessionUser, http.MethodPost, "/step-up/2fa")
	requireRoute(t, sessionUser, http.MethodPost, "/oidc/{provider}/link/start")
	requireRoute(t, sessionUser, http.MethodPost, "/oidc/{provider}/step-up/start")
	requireRoute(t, sessionUser, http.MethodPost, "/solana/challenge")
	requireRoute(t, sessionUser, http.MethodPost, "/solana/link")
	requireRoute(t, sessionUser, http.MethodPost, "/email/verify/request")
	requireRoute(t, sessionUser, http.MethodPost, "/phone/verify/request")
	requireNoRoute(t, sessionUser, http.MethodPost, "/register")
	requireNoRoute(t, sessionUser, http.MethodGet, "/user/me")
	requireNoRoute(t, sessionUser, http.MethodGet, "/me/bootstrap")

	admin := s.APIRoutes(RouteAdmin)
	requireRoute(t, admin, http.MethodPost, "/admin/users/{user_id}/ban")
	requireRoute(t, admin, http.MethodPost, "/admin/users/{user_id}/unban")
	requireRoute(t, admin, http.MethodPost, "/admin/users/{user_id}/recover")
	requireNoRoute(t, admin, http.MethodPost, "/admin/users/ban")
	requireNoRoute(t, admin, http.MethodPost, "/admin/users/unban")
	requireNoRoute(t, admin, http.MethodPost, "/admin/users/toggle-active")

	permissions := s.APIRoutes(RoutePermissionGroups)
	requireNoRoute(t, permissions, http.MethodPost, "/root/{instance_slug}/members")
	requireNoRoute(t, permissions, http.MethodGet, "/me/groups")
	requireNoRoute(t, permissions, http.MethodPost, "/invites/redeem")
	requireNoRoute(t, permissions, http.MethodGet, "/me/permissions")
	requireNoRoute(t, permissions, http.MethodPost, "/password/login")

	requireRoute(t, s.APIRoutes(RouteAccount), http.MethodGet, "/me/permissions")
	requireRoute(t, s.Routes().DefaultAPI(), http.MethodGet, "/auth/capabilities")
	requireNoRoute(t, s.Routes().DefaultAPI(), http.MethodGet, "/identity-providers")
	requireNoRoute(t, s.Routes().DefaultAPI(), http.MethodGet, "/providers")
}

func TestAPIRoutesAreConfigAwareForAuthFeatures(t *testing.T) {
	off := newRouteFeatureTestService(t, func(cfg *authcore.Config) {
		cfg.Registration.NativeUserMode = embedded.RegistrationModeClosed
		cfg.TwoFactor.Mode = embedded.TwoFactorDisabled
	})
	requireNoRoute(t, off.APIRoutes(RouteRegistration), http.MethodPost, "/register")
	requireRoute(t, off.APIRoutes(RouteRegistration), http.MethodGet, "/register/availability")
	requireNoRoute(t, off.APIRoutes(RouteAuth), http.MethodPost, "/passwordless/start")
	requireNoRoute(t, off.APIRoutes(RouteAccount), http.MethodPost, "/step-up/2fa")
	requireNoRoute(t, off.APIRoutes(RouteAuth), http.MethodPost, "/2fa/verify")
	requireNoRoute(t, off.APIRoutes(RouteAuth), http.MethodPost, "/solana/challenge")
	requireNoRoute(t, off.APIRoutes(RouteAccount), http.MethodPost, "/oidc/{provider}/link/start")
	requireNoRoute(t, off.Routes().OIDCBrowser(), http.MethodGet, "/{provider}/login")

	on := newRouteFeatureTestService(t, func(cfg *authcore.Config) {
		cfg.Registration.PasswordlessLogin = true
		cfg.SolanaNetwork = "devnet"
	})
	enableTestOIDCProvider(on)
	requireRoute(t, on.APIRoutes(RouteRegistration), http.MethodPost, "/register")
	requireRoute(t, on.APIRoutes(RouteAuth), http.MethodPost, "/passwordless/start")
	requireRoute(t, on.APIRoutes(RouteAccount), http.MethodPost, "/step-up/2fa")
	requireRoute(t, on.APIRoutes(RouteAuth), http.MethodPost, "/2fa/verify")
	requireRoute(t, on.APIRoutes(RouteAuth), http.MethodPost, "/solana/challenge")
	requireRoute(t, on.APIRoutes(RouteAccount), http.MethodPost, "/oidc/{provider}/link/start")
	requireRoute(t, on.Routes().OIDCBrowser(), http.MethodGet, "/{provider}/login")
}

func TestPermissionGroupDiscoveryRoutesAreConfigAware(t *testing.T) {
	s := newTestServiceWithRBAC(t,
		embedded.PersonaDef{
			Name: "org", Parent: embedded.RootPersona,
		},
	)
	requireRoute(t, s.APIRoutes(RouteAccount), http.MethodGet, "/me/groups")
	requireNoRoute(t, s.APIRoutes(RoutePermissionGroups), http.MethodGet, "/me/groups")
	requireRoute(t, s.APIRoutes(RoutePermissionGroups), http.MethodPost, "/invites/redeem")

	invites := newTestServiceWithRBAC(t,
		embedded.PersonaDef{
			Name: "org", Parent: embedded.RootPersona,
		},
	)
	requireRoute(t, invites.APIRoutes(RoutePermissionGroups), http.MethodPost, "/invites/redeem")
}

func TestPasskeyRoutesGatedOnPasskeyConfig(t *testing.T) {
	// No PasskeyConfig (RPID unset): the /passkeys/* routes are not mounted, so
	// the embedder never exposes WebAuthn endpoints that can only fail.
	off := newTestService(t)
	require.False(t, off.svc.PasskeysEnabled())
	requireNoRoute(t, off.APIRoutes(RouteAccount), http.MethodGet, "/passkeys")
	requireNoRoute(t, off.APIRoutes(RouteAuth), http.MethodPost, "/passkeys/login/begin")
	requireNoRoute(t, off.Routes().DefaultAPI(), http.MethodPost, "/passkeys/login/begin")

	// With an RPID configured, the passkey routes appear.
	on := newTestServiceWithPasskeys(t)
	require.True(t, on.svc.PasskeysEnabled())
	requireRoute(t, on.APIRoutes(RouteAccount), http.MethodGet, "/passkeys")
	requireRoute(t, on.APIRoutes(RouteAuth), http.MethodPost, "/passkeys/login/begin")
	requireRoute(t, on.Routes().DefaultAPI(), http.MethodPost, "/passkeys/login/begin")
}

func newTestServiceWithRBAC(t *testing.T, personas ...embedded.PersonaDef) *Service {
	t.Helper()
	cfg := authcore.Config{
		Token: authcore.TokenConfig{
			Issuer:            "https://example.com",
			IssuedAudiences:   []string{"test-app"},
			ExpectedAudiences: []string{"test-app"},
		},
		Registration: authcore.RegistrationConfig{Verification: authcore.RegistrationVerificationNone},
		RBAC:         personas,
	}
	coreSvc, err := authcore.NewFromConfig(cfg, nil)
	require.NoError(t, err)
	return serviceFromCore(t, coreSvc)
}

func newRouteFeatureTestService(t *testing.T, configure func(*authcore.Config)) *Service {
	t.Helper()
	cfg := authcore.Config{
		Token: authcore.TokenConfig{
			Issuer:            "https://example.com",
			IssuedAudiences:   []string{"test-app"},
			ExpectedAudiences: []string{"test-app"},
		},
		Registration: authcore.RegistrationConfig{Verification: authcore.RegistrationVerificationNone},
	}
	if configure != nil {
		configure(&cfg)
	}
	coreSvc, err := authcore.NewFromConfig(cfg, nil)
	require.NoError(t, err)
	return serviceFromCore(t, coreSvc)
}

func TestCapabilitiesEndpoint(t *testing.T) {
	s := newTestService(t)
	rec := httptest.NewRecorder()
	s.handleCapabilitiesGET(rec, httptest.NewRequest(http.MethodGet, "/auth/capabilities", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotEmpty(t, rec.Header().Get("ETag"))
	require.Contains(t, rec.Header().Get("Cache-Control"), "max-age=300")

	var body struct {
		Registration struct {
			Mode string `json:"mode"`
		} `json:"registration"`
		Providers []any `json:"providers"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "open", body.Registration.Mode)
	require.NotNil(t, body.Providers)
}

func TestOIDCBrowserRoutesArePrefixNeutral(t *testing.T) {
	s := newTestService(t)
	enableTestOIDCProvider(s)

	routes := s.Routes().OIDCBrowser()
	requireRoute(t, routes, http.MethodGet, "/{provider}/login")
	requireRoute(t, routes, http.MethodGet, "/{provider}/callback")
	requireRoute(t, routes, http.MethodGet, "/{provider}/step-up/callback")
	requireNoRoute(t, routes, http.MethodGet, "/oidc/{provider}/login")
	requireNoRoute(t, s.APIRoutes(RouteAuth, RouteAccount), http.MethodGet, "/{provider}/login")
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
