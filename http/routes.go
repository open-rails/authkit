package authhttp

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/embedded"
)

// RouteGroup identifies a prefix-neutral AuthKit route capability. Host
// applications can mount all default groups or select only the capabilities
// they want to expose.
type RouteGroup string

const (
	RouteAuth             RouteGroup = "auth"
	RouteRegistration     RouteGroup = "registration"
	RouteAccount          RouteGroup = "account"
	RouteAdmin            RouteGroup = "admin"
	RoutePermissionGroups RouteGroup = "permission_groups"
	RouteBrowserOIDC      RouteGroup = "browser_oidc"
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
		return required(s.requirePermission(embedded.RootPersona, "", perm, h))
	}
	optional := Optional(s.verifier)
	lang := func(h http.Handler) http.Handler { return LanguageMiddleware(s.langCfg)(h) }
	routes := []RouteSpec{
		{Method: http.MethodGet, Path: "/auth/capabilities", Group: RouteAuth, Handler: http.HandlerFunc(s.handleCapabilitiesGET)},

		{Method: http.MethodPost, Path: "/token", Group: RouteAuth, Handler: http.HandlerFunc(s.handleAuthTokenPOST)},
		{Method: http.MethodPost, Path: "/sessions/current", Group: RouteAuth, Handler: http.HandlerFunc(s.handleAuthSessionsCurrentPOST)},
		{Method: http.MethodDelete, Path: "/logout", Group: RouteAuth, Handler: required(http.HandlerFunc(s.handleLogoutDELETE))},
		{Method: http.MethodPost, Path: "/password/login", Group: RouteAuth, Handler: http.HandlerFunc(s.handlePasswordLoginPOST)},
		{Method: http.MethodPost, Path: "/passwordless/start", Group: RouteAuth, Handler: http.HandlerFunc(s.handlePasswordlessStartPOST)},
		{Method: http.MethodPost, Path: "/passwordless/confirm", Group: RouteAuth, Handler: http.HandlerFunc(s.handlePasswordlessConfirmPOST)},
		{Method: http.MethodPost, Path: "/passkeys/login/begin", Group: RouteAuth, Handler: http.HandlerFunc(s.handlePasskeyLoginBeginPOST)},
		{Method: http.MethodPost, Path: "/passkeys/login/finish", Group: RouteAuth, Handler: http.HandlerFunc(s.handlePasskeyLoginFinishPOST)},
		{Method: http.MethodPost, Path: "/email/password/reset/request", Group: RouteAuth, Handler: http.HandlerFunc(s.handleEmailPasswordResetRequestPOST)},
		{Method: http.MethodGet, Path: "/email/password/reset/confirm", Group: RouteAuth, Handler: http.HandlerFunc(s.handleEmailPasswordResetConfirmGET)},
		{Method: http.MethodPost, Path: "/email/password/reset/confirm", Group: RouteAuth, Handler: http.HandlerFunc(s.handleEmailPasswordResetConfirmPOST)},
		{Method: http.MethodPost, Path: "/phone/password/reset/request", Group: RouteAuth, Handler: http.HandlerFunc(s.handlePhonePasswordResetRequestPOST)},
		{Method: http.MethodGet, Path: "/phone/password/reset/confirm", Group: RouteAuth, Handler: http.HandlerFunc(s.handlePhonePasswordResetConfirmGET)},
		{Method: http.MethodPost, Path: "/phone/password/reset/confirm", Group: RouteAuth, Handler: http.HandlerFunc(s.handlePhonePasswordResetConfirmPOST)},

		{Method: http.MethodPost, Path: "/register", Group: RouteRegistration, Handler: http.HandlerFunc(s.handleRegisterUnifiedPOST)},
		{Method: http.MethodGet, Path: "/register/availability", Group: RouteRegistration, Handler: http.HandlerFunc(s.handleRegisterAvailabilityGET)},
		{Method: http.MethodPost, Path: "/register/resend-email", Group: RouteRegistration, Handler: http.HandlerFunc(s.handlePendingRegistrationResendPOST)},
		{Method: http.MethodPost, Path: "/register/resend-phone", Group: RouteRegistration, Handler: http.HandlerFunc(s.handlePhoneRegisterResendPOST)},
		{Method: http.MethodPost, Path: "/register/abandon", Group: RouteRegistration, Handler: http.HandlerFunc(s.handlePendingRegistrationAbandonPOST)},

		{Method: http.MethodPost, Path: "/email/verify/request", Group: RouteAccount, Handler: optional(http.HandlerFunc(s.handleEmailVerifyRequestPOST))},
		{Method: http.MethodGet, Path: "/email/verify/confirm", Group: RouteAccount, Handler: http.HandlerFunc(s.handleEmailVerifyConfirmGET)},
		{Method: http.MethodPost, Path: "/email/verify/confirm", Group: RouteAccount, Handler: optional(http.HandlerFunc(s.handleEmailVerifyConfirmPOST))},

		{Method: http.MethodPost, Path: "/phone/verify/request", Group: RouteAccount, Handler: optional(http.HandlerFunc(s.handlePhoneVerifyRequestPOST))},
		{Method: http.MethodGet, Path: "/phone/verify/confirm", Group: RouteAccount, Handler: http.HandlerFunc(s.handlePhoneVerifyConfirmGET)},
		{Method: http.MethodPost, Path: "/phone/verify/confirm", Group: RouteAccount, Handler: optional(http.HandlerFunc(s.handlePhoneVerifyConfirmPOST))},

		{Method: http.MethodPost, Path: "/user/password", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handleUserPasswordPOST))},
		{Method: http.MethodGet, Path: "/user/sessions", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handleUserSessionsGET))},
		{Method: http.MethodDelete, Path: "/user/sessions/{id}", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handleUserSessionDELETE))},
		{Method: http.MethodDelete, Path: "/user/sessions", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handleUserSessionsDELETE))},
		{Method: http.MethodGet, Path: "/me", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handleUserMeGET))},
		// #147 known-user permission-group invites: accepted/declined with the caller's own auth.
		{Method: http.MethodGet, Path: "/me/group-invites", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handleMeGroupInvitesGET))},
		{Method: http.MethodPost, Path: "/me/group-invites/{id}/accept", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handleMeGroupInviteAccept))},
		{Method: http.MethodPost, Path: "/me/group-invites/{id}/decline", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handleMeGroupInviteDecline))},
		{Method: http.MethodPatch, Path: "/user/username", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handleUserUsernamePATCH))},
		{Method: http.MethodPatch, Path: "/user/preferred-language", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handleUserPreferredLanguagePATCH))},
		{Method: http.MethodPatch, Path: "/user/biography", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handleUserBiographyPATCH))},
		{Method: http.MethodDelete, Path: "/user", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handleUserDeleteDELETE))},
		{Method: http.MethodDelete, Path: "/user/providers/{provider}", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handleUserUnlinkProviderDELETE))},
		{Method: http.MethodPost, Path: "/passkeys/register/begin", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handlePasskeyRegisterBeginPOST))},
		{Method: http.MethodPost, Path: "/passkeys/register/finish", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handlePasskeyRegisterFinishPOST))},
		{Method: http.MethodGet, Path: "/passkeys", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handlePasskeysGET))},
		{Method: http.MethodPatch, Path: "/passkeys/{id}", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handlePasskeyPATCH))},
		{Method: http.MethodDelete, Path: "/passkeys/{id}", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handlePasskeyDELETE))},

		{Method: http.MethodPost, Path: "/step-up/password", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handlePasswordStepUpPOST))},
		{Method: http.MethodPost, Path: "/step-up/2fa", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handleTwoFactorStepUpPOST))},

		{Method: http.MethodPost, Path: "/oidc/{provider}/link/start", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handleOIDCLinkStartPOST))},
		{Method: http.MethodPost, Path: "/oidc/{provider}/step-up/start", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handleOIDCStepUpStartPOST))},

		{Method: http.MethodGet, Path: "/user/2fa", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handleUser2FAStatusGET))},
		{Method: http.MethodPost, Path: "/user/2fa", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handleUser2FAPOST))},
		{Method: http.MethodDelete, Path: "/user/2fa", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handleUser2FADELETE))},
		{Method: http.MethodPost, Path: "/user/2fa/backup-codes", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handleUser2FABackupCodesPOST))},
		{Method: http.MethodPost, Path: "/2fa/challenge", Group: RouteAuth, Handler: http.HandlerFunc(s.handleUser2FAChallengePOST)},
		{Method: http.MethodPost, Path: "/2fa/verify", Group: RouteAuth, Handler: http.HandlerFunc(s.handleUser2FAVerifyPOST)},

		{Method: http.MethodPost, Path: "/solana/challenge", Group: RouteAuth, Handler: http.HandlerFunc(s.handleSolanaChallengePOST)},
		{Method: http.MethodPost, Path: "/solana/login", Group: RouteAuth, Handler: http.HandlerFunc(s.handleSolanaLoginPOST)},
		{Method: http.MethodPost, Path: "/solana/link", Group: RouteAccount, Handler: required(http.HandlerFunc(s.handleSolanaLinkPOST))},

		// Intrinsic user-admin directory. Auth is permission-based: human users
		// authorize through the root permission-group, programmatic principals via
		// their verified permission ceiling.
		{Method: http.MethodGet, Path: "/admin/users", Group: RouteAdmin, Handler: rootPermission(embedded.PermRootResourcesRead, s.handleAdminUsersListGET)},
		{Method: http.MethodGet, Path: "/admin/users/{user_id}", Group: RouteAdmin, Handler: rootPermission(embedded.PermRootResourcesRead, s.handleAdminUserGET)},
		{Method: http.MethodGet, Path: "/admin/users/{user_id}/signins", Group: RouteAdmin, Handler: rootPermission(embedded.PermRootResourcesRead, s.handleAdminUserSigninsGET)},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/ban", Group: RouteAdmin, Handler: rootPermission(embedded.PermRootUsersBan, s.handleAdminUsersBanPOST)},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/unban", Group: RouteAdmin, Handler: rootPermission(embedded.PermRootUsersBan, s.handleAdminUsersUnbanPOST)},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/recover", Group: RouteAdmin, Handler: rootPermission(embedded.PermRootUsersRecover, s.handleAdminUserRecoverPOST)},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/sessions/revoke", Group: RouteAdmin, Handler: rootPermission(embedded.PermRootUsersRecover, s.handleAdminUserSessionsRevokePOST)},
		{Method: http.MethodDelete, Path: "/admin/users/{user_id}", Group: RouteAdmin, Handler: rootPermission(embedded.PermRootUsersDelete, s.handleAdminUserDeleteDELETE)},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/restore", Group: RouteAdmin, Handler: rootPermission(embedded.PermRootUsersDelete, s.handleAdminUserRestorePOST)},
	}

	// Passkey routes are mounted only when passkeys are configured. Without a
	// Relying Party ID the WebAuthn ceremonies fail closed, so exposing the
	// /passkeys/* endpoints would just serve guaranteed errors. Embedders that
	// set PasskeyConfig.RPID get the routes; everyone else doesn't advertise a
	// feature they can't fulfil.
	passkeysEnabled := s.svc.PasskeysEnabled()
	opts := s.svc.Options()
	passwordlessEnabled := opts.PasswordlessLoginEnabled
	registrationEnabled := opts.NativeUserRegistrationMode != embedded.RegistrationModeClosed
	twoFactorEnabled := s.svc.TwoFactorEnabled()
	solanaEnabled := strings.TrimSpace(opts.SolanaNetwork) != ""
	oidcEnabled := len(s.authProviders()) > 0
	out := make([]RouteSpec, 0, len(routes))
	for _, route := range routes {
		if !selected(route.Group) {
			continue
		}
		if isPasskeyPath(route.Path) && !passkeysEnabled {
			continue
		}
		if isPasswordlessPath(route.Path) && !passwordlessEnabled {
			continue
		}
		if isRegistrationMutationPath(route.Path) && !registrationEnabled {
			continue
		}
		if isTwoFactorPath(route.Path) && !twoFactorEnabled {
			continue
		}
		if isSolanaPath(route.Path) && !solanaEnabled {
			continue
		}
		if isOIDCPath(route.Path) && !oidcEnabled {
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

func isPasskeyPath(path string) bool {
	return path == "/passkeys" || strings.HasPrefix(path, "/passkeys/")
}

func isPasswordlessPath(path string) bool {
	return path == "/passwordless/start" || path == "/passwordless/confirm"
}

func isRegistrationMutationPath(path string) bool {
	return path == "/register" || path == "/register/abandon" || strings.HasPrefix(path, "/register/resend-")
}

func isTwoFactorPath(path string) bool {
	return path == "/step-up/2fa" || path == "/user/2fa" || strings.HasPrefix(path, "/user/2fa/") || strings.HasPrefix(path, "/2fa/")
}

func isSolanaPath(path string) bool {
	return strings.HasPrefix(path, "/solana/")
}

func isOIDCPath(path string) bool {
	return strings.HasPrefix(path, "/oidc/")
}

// OIDCBrowserRoutes returns browser redirect routes with no mount prefix.
func (s *Service) OIDCBrowserRoutes(groups ...RouteGroup) []RouteSpec {
	if s == nil || s.svc == nil {
		return nil
	}
	if len(s.authProviders()) == 0 {
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
