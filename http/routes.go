package authhttp

import (
	"net/http"

	core "github.com/open-rails/authkit/core"
)

// RouteGroup identifies a prefix-neutral AuthKit route capability. Host
// applications can mount all default groups or select only the capabilities
// they want to expose.
type RouteGroup string

const (
	RoutePublic      RouteGroup = "public"
	RouteRegister    RouteGroup = "register"
	RouteSession     RouteGroup = "session"
	RouteUser        RouteGroup = "user"
	RouteAdmin       RouteGroup = "admin"
	RouteBrowserOIDC RouteGroup = "browser_oidc"
	RoutePasskeys    RouteGroup = "passkeys"
)

// RouteSpec is a concrete, prefix-neutral route with its AuthKit handler
// attached. Path parameters use net/http ServeMux syntax, e.g.
// "/namespaces/{slug}".
type RouteSpec struct {
	Method  string
	Path    string
	Group   RouteGroup
	Handler http.Handler
}

// Routes provides access to AuthKit's canonical route groups.
type Routes struct {
	svc *Service
}

// Routes returns AuthKit's canonical route registry for this service.
func (s *Service) Routes() Routes {
	return Routes{svc: s}
}

// DefaultAPI returns every AuthKit JSON API route enabled by this service.
func (r Routes) DefaultAPI() []RouteSpec {
	if r.svc == nil {
		return nil
	}
	return r.svc.APIRoutes()
}

// Groups returns every enabled AuthKit JSON API route in the requested groups.
func (r Routes) Groups(groups ...RouteGroup) []RouteSpec {
	if r.svc == nil {
		return nil
	}
	return r.svc.APIRoutes(groups...)
}

// OIDCBrowser returns browser redirect OIDC routes without a mount prefix.
// Host applications choose where to mount them, commonly "/oidc".
func (r Routes) OIDCBrowser() []RouteSpec {
	if r.svc == nil {
		return nil
	}
	return r.svc.OIDCBrowserRoutes()
}

// PermissionGroups returns the auto-generated per-persona group-management
// routes (members, roles, etc.) implied by this service's declared
// permission-group schema, plus the cross-persona GET /me/groups discovery
// route. These are also included in DefaultAPI; this accessor lets a host mount
// only the group-management surface. See Service.PermissionGroupRoutes.
func (r Routes) PermissionGroups() []RouteSpec {
	if r.svc == nil {
		return nil
	}
	return r.svc.PermissionGroupRoutes()
}

// APIRoutes returns AuthKit's enabled JSON API routes. With no groups it
// returns the default API surface. With groups, it returns only matching routes.
func (s *Service) APIRoutes(groups ...RouteGroup) []RouteSpec {
	if s == nil || s.svc == nil || s.verifier == nil {
		return nil
	}
	selected := routeGroupSet(groups)
	required := Required(s.verifier)
	// rootPermission gates an intrinsic, root-scoped route on a `root:*`
	// permission through the granular permission system (svc.Can for users,
	// the verified ceiling for machine principals — see requirePermission).
	// There is no bespoke "admin" auth tier; these are plain root-group perms.
	rootPermission := func(perm string, h http.HandlerFunc) http.Handler {
		return required(s.requirePermission(core.RootPersona, "", perm, h))
	}
	optional := Optional(s.verifier)
	lang := func(h http.Handler) http.Handler { return LanguageMiddleware(s.langCfg)(h) }
	routes := []RouteSpec{
		{Method: http.MethodGet, Path: "/identity-providers", Group: RoutePublic, Handler: http.HandlerFunc(s.handleProvidersGET)},

		{Method: http.MethodPost, Path: "/token", Group: RouteSession, Handler: http.HandlerFunc(s.handleAuthTokenPOST)},
		{Method: http.MethodPost, Path: "/sessions/current", Group: RouteSession, Handler: http.HandlerFunc(s.handleAuthSessionsCurrentPOST)},
		{Method: http.MethodDelete, Path: "/logout", Group: RouteSession, Handler: required(http.HandlerFunc(s.handleLogoutDELETE))},
		{Method: http.MethodPost, Path: "/password/login", Group: RouteSession, Handler: http.HandlerFunc(s.handlePasswordLoginPOST)},
		{Method: http.MethodPost, Path: "/passkeys/login/begin", Group: RoutePasskeys, Handler: http.HandlerFunc(s.handlePasskeyLoginBeginPOST)},
		{Method: http.MethodPost, Path: "/passkeys/login/finish", Group: RoutePasskeys, Handler: http.HandlerFunc(s.handlePasskeyLoginFinishPOST)},
		{Method: http.MethodPost, Path: "/email/password/reset/request", Group: RouteSession, Handler: http.HandlerFunc(s.handleEmailPasswordResetRequestPOST)},
		{Method: http.MethodGet, Path: "/email/password/reset/confirm", Group: RouteSession, Handler: http.HandlerFunc(s.handleEmailPasswordResetConfirmGET)},
		{Method: http.MethodPost, Path: "/email/password/reset/confirm", Group: RouteSession, Handler: http.HandlerFunc(s.handleEmailPasswordResetConfirmPOST)},
		{Method: http.MethodPost, Path: "/phone/password/reset/request", Group: RouteSession, Handler: http.HandlerFunc(s.handlePhonePasswordResetRequestPOST)},
		{Method: http.MethodGet, Path: "/phone/password/reset/confirm", Group: RouteSession, Handler: http.HandlerFunc(s.handlePhonePasswordResetConfirmGET)},
		{Method: http.MethodPost, Path: "/phone/password/reset/confirm", Group: RouteSession, Handler: http.HandlerFunc(s.handlePhonePasswordResetConfirmPOST)},

		{Method: http.MethodPost, Path: "/register", Group: RouteRegister, Handler: http.HandlerFunc(s.handleRegisterUnifiedPOST)},
		{Method: http.MethodGet, Path: "/register/availability", Group: RouteRegister, Handler: http.HandlerFunc(s.handleRegisterAvailabilityGET)},
		{Method: http.MethodPost, Path: "/register/resend-email", Group: RouteRegister, Handler: http.HandlerFunc(s.handlePendingRegistrationResendPOST)},
		{Method: http.MethodPost, Path: "/register/resend-phone", Group: RouteRegister, Handler: http.HandlerFunc(s.handlePhoneRegisterResendPOST)},
		{Method: http.MethodPost, Path: "/register/abandon", Group: RouteRegister, Handler: http.HandlerFunc(s.handlePendingRegistrationAbandonPOST)},

		{Method: http.MethodPost, Path: "/email/verify/request", Group: RouteRegister, Handler: optional(http.HandlerFunc(s.handleEmailVerifyRequestPOST))},
		{Method: http.MethodGet, Path: "/email/verify/confirm", Group: RouteRegister, Handler: http.HandlerFunc(s.handleEmailVerifyConfirmGET)},
		{Method: http.MethodPost, Path: "/email/verify/confirm", Group: RouteRegister, Handler: optional(http.HandlerFunc(s.handleEmailVerifyConfirmPOST))},

		{Method: http.MethodPost, Path: "/phone/verify/request", Group: RouteRegister, Handler: optional(http.HandlerFunc(s.handlePhoneVerifyRequestPOST))},
		{Method: http.MethodGet, Path: "/phone/verify/confirm", Group: RouteRegister, Handler: http.HandlerFunc(s.handlePhoneVerifyConfirmGET)},
		{Method: http.MethodPost, Path: "/phone/verify/confirm", Group: RouteRegister, Handler: optional(http.HandlerFunc(s.handlePhoneVerifyConfirmPOST))},

		{Method: http.MethodPost, Path: "/user/password", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserPasswordPOST))},
		{Method: http.MethodGet, Path: "/user/sessions", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserSessionsGET))},
		{Method: http.MethodDelete, Path: "/user/sessions/{id}", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserSessionDELETE))},
		{Method: http.MethodDelete, Path: "/user/sessions", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserSessionsDELETE))},
		{Method: http.MethodGet, Path: "/me", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserMeGET))},
		{Method: http.MethodPatch, Path: "/user/username", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserUsernamePATCH))},
		{Method: http.MethodPatch, Path: "/user/preferred-language", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserPreferredLanguagePATCH))},
		{Method: http.MethodPatch, Path: "/user/biography", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserBiographyPATCH))},
		{Method: http.MethodDelete, Path: "/user", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserDeleteDELETE))},
		{Method: http.MethodDelete, Path: "/user/providers/{provider}", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserUnlinkProviderDELETE))},
		{Method: http.MethodPost, Path: "/passkeys/register/begin", Group: RoutePasskeys, Handler: required(http.HandlerFunc(s.handlePasskeyRegisterBeginPOST))},
		{Method: http.MethodPost, Path: "/passkeys/register/finish", Group: RoutePasskeys, Handler: required(http.HandlerFunc(s.handlePasskeyRegisterFinishPOST))},
		{Method: http.MethodGet, Path: "/passkeys", Group: RoutePasskeys, Handler: required(http.HandlerFunc(s.handlePasskeysGET))},
		{Method: http.MethodPatch, Path: "/passkeys/{id}", Group: RoutePasskeys, Handler: required(http.HandlerFunc(s.handlePasskeyPATCH))},
		{Method: http.MethodDelete, Path: "/passkeys/{id}", Group: RoutePasskeys, Handler: required(http.HandlerFunc(s.handlePasskeyDELETE))},

		{Method: http.MethodPost, Path: "/step-up/password", Group: RouteUser, Handler: required(http.HandlerFunc(s.handlePasswordStepUpPOST))},
		{Method: http.MethodPost, Path: "/step-up/2fa", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleTwoFactorStepUpPOST))},

		{Method: http.MethodPost, Path: "/oidc/{provider}/link/start", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleOIDCLinkStartPOST))},
		{Method: http.MethodPost, Path: "/oidc/{provider}/step-up/start", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleOIDCStepUpStartPOST))},

		{Method: http.MethodGet, Path: "/user/2fa", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUser2FAStatusGET))},
		{Method: http.MethodPost, Path: "/user/2fa", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUser2FAPOST))},
		{Method: http.MethodDelete, Path: "/user/2fa", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUser2FADELETE))},
		{Method: http.MethodPost, Path: "/user/2fa/backup-codes", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUser2FABackupCodesPOST))},
		{Method: http.MethodPost, Path: "/2fa/challenge", Group: RouteSession, Handler: http.HandlerFunc(s.handleUser2FAChallengePOST)},
		{Method: http.MethodPost, Path: "/2fa/verify", Group: RouteSession, Handler: http.HandlerFunc(s.handleUser2FAVerifyPOST)},

		{Method: http.MethodPost, Path: "/solana/challenge", Group: RouteSession, Handler: http.HandlerFunc(s.handleSolanaChallengePOST)},
		{Method: http.MethodPost, Path: "/solana/login", Group: RouteSession, Handler: http.HandlerFunc(s.handleSolanaLoginPOST)},
		{Method: http.MethodPost, Path: "/solana/link", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleSolanaLinkPOST))},

		// Intrinsic user-admin directory. Auth is permission-based: human users
		// authorize through the root permission-group, programmatic principals via
		// their verified permission ceiling.
		{Method: http.MethodGet, Path: "/admin/users", Group: RouteAdmin, Handler: rootPermission(core.PermRootResourcesRead, s.handleAdminUsersListGET)},
		{Method: http.MethodGet, Path: "/admin/users/{user_id}", Group: RouteAdmin, Handler: rootPermission(core.PermRootResourcesRead, s.handleAdminUserGET)},
		{Method: http.MethodGet, Path: "/admin/users/{user_id}/signins", Group: RouteAdmin, Handler: rootPermission(core.PermRootResourcesRead, s.handleAdminUserSigninsGET)},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/ban", Group: RouteAdmin, Handler: rootPermission(core.PermRootUsersBan, s.handleAdminUsersBanPOST)},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/unban", Group: RouteAdmin, Handler: rootPermission(core.PermRootUsersBan, s.handleAdminUsersUnbanPOST)},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/recover", Group: RouteAdmin, Handler: rootPermission(core.PermRootUsersRecover, s.handleAdminUserRecoverPOST)},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/sessions/revoke", Group: RouteAdmin, Handler: rootPermission(core.PermRootUsersRecover, s.handleAdminUserSessionsRevokePOST)},
		{Method: http.MethodDelete, Path: "/admin/users/{user_id}", Group: RouteAdmin, Handler: rootPermission(core.PermRootUsersDelete, s.handleAdminUserDeleteDELETE)},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/restore", Group: RouteAdmin, Handler: rootPermission(core.PermRootUsersDelete, s.handleAdminUserRestorePOST)},
	}

	out := make([]RouteSpec, 0, len(routes))
	for _, route := range routes {
		if !selected(route.Group) {
			continue
		}
		route.Handler = lang(route.Handler)
		out = append(out, route)
	}

	// #111: the auto-generated per-persona group-management surface is
	// schema-DERIVED (not a static table), so it is appended here rather than
	// listed above. Its handlers already carry the required + language middleware
	// (PermissionGroupRoutes wraps them), so they are not re-wrapped with lang.
	for _, route := range s.PermissionGroupRoutes() {
		if !selected(route.Group) {
			continue
		}
		out = append(out, route)
	}
	return out
}

// OIDCBrowserRoutes returns browser redirect routes with no mount prefix.
func (s *Service) OIDCBrowserRoutes(groups ...RouteGroup) []RouteSpec {
	if s == nil || s.svc == nil {
		return nil
	}
	selected := routeGroupSet(groups)
	lang := func(h http.Handler) http.Handler { return LanguageMiddleware(s.langCfg)(h) }
	routes := []RouteSpec{
		{Method: http.MethodGet, Path: "/{provider}/login", Group: RouteBrowserOIDC, Handler: http.HandlerFunc(s.handleOIDCLoginGET)},
		{Method: http.MethodGet, Path: "/{provider}/callback", Group: RouteBrowserOIDC, Handler: http.HandlerFunc(s.handleOIDCCallbackGET)},
		{Method: http.MethodGet, Path: "/{provider}/step-up/callback", Group: RouteBrowserOIDC, Handler: http.HandlerFunc(s.handleOIDCCallbackGET)},
	}
	out := make([]RouteSpec, 0, len(routes))
	for _, route := range routes {
		if !selected(route.Group) {
			continue
		}
		route.Handler = lang(route.Handler)
		out = append(out, route)
	}
	return out
}

func routeGroupSet(groups []RouteGroup) func(RouteGroup) bool {
	if len(groups) == 0 {
		return func(RouteGroup) bool { return true }
	}
	set := make(map[RouteGroup]struct{}, len(groups))
	for _, group := range groups {
		set[group] = struct{}{}
	}
	return func(group RouteGroup) bool {
		_, ok := set[group]
		return ok
	}
}
