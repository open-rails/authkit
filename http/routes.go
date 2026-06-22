package authhttp

import (
	"net/http"
)

// RouteGroup identifies a prefix-neutral AuthKit route capability. Host
// applications can mount all default groups or select only the capabilities
// they want to expose.
type RouteGroup string

const (
	RouteCore               RouteGroup = "core"
	RoutePassword           RouteGroup = "password"
	RouteRegister           RouteGroup = "register"
	RouteOwners             RouteGroup = "owners"
	RouteEmailVerification  RouteGroup = "email_verification"
	RoutePhoneVerification  RouteGroup = "phone_verification"
	RouteOrgs               RouteGroup = "orgs"
	RouteUser               RouteGroup = "user"
	RouteAccountOIDCLinking RouteGroup = "account_oidc_linking"
	RouteTwoFactor          RouteGroup = "two_factor"
	RouteSolana             RouteGroup = "solana"
	RouteAdmin              RouteGroup = "admin"
	RouteOIDCBrowser        RouteGroup = "oidc_browser"
	// RouteOrgIssuers exposes the inbound accept-side org-issuer registry
	// routes (the home for what tensorhub previously exposed as
	// `/api/v1/platform/issuers`).
	RouteOrgIssuers RouteGroup = "federation"
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

// APIRoutes returns AuthKit's enabled JSON API routes. With no groups it
// returns the default API surface. With groups, it returns only matching routes.
func (s *Service) APIRoutes(groups ...RouteGroup) []RouteSpec {
	if s == nil || s.svc == nil || s.verifier == nil {
		return nil
	}
	selected := routeGroupSet(groups)
	required := Required(s.verifier)
	lang := func(h http.Handler) http.Handler { return LanguageMiddleware(s.langCfg)(h) }
	// notFoundHandler explicitly 404s a removed path that an adjacent wildcard
	// route would otherwise capture (e.g. POST /admin/users/toggle-active would
	// match GET /admin/users/{user_id} → 405). These are 404 sentinels.
	notFoundHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		notFound(w, ErrNotFound)
	})

	routes := []RouteSpec{
		{Method: http.MethodPost, Path: "/token", Group: RouteCore, Handler: http.HandlerFunc(s.handleAuthTokenPOST)},
		{Method: http.MethodGet, Path: "/identity-providers", Group: RouteCore, Handler: http.HandlerFunc(s.handleProvidersGET)},
		{Method: http.MethodPost, Path: "/sessions/current", Group: RouteCore, Handler: http.HandlerFunc(s.handleAuthSessionsCurrentPOST)},
		{Method: http.MethodDelete, Path: "/logout", Group: RouteCore, Handler: required(http.HandlerFunc(s.handleLogoutDELETE))},
		// "What are my permissions" introspection (#76 amendment): the caller's
		// GRANTED ceiling + identity, for any programmatic principal.
		{Method: http.MethodGet, Path: "/me/permissions", Group: RouteCore, Handler: required(http.HandlerFunc(s.handleMePermissionsGET))},
		{Method: http.MethodPost, Path: "/reauth/password", Group: RoutePassword, Handler: required(http.HandlerFunc(s.handlePasswordReauthPOST))},

		{Method: http.MethodPost, Path: "/password/login", Group: RoutePassword, Handler: http.HandlerFunc(s.handlePasswordLoginPOST)},
		{Method: http.MethodPost, Path: "/email/password/reset/request", Group: RoutePassword, Handler: http.HandlerFunc(s.handleEmailPasswordResetRequestPOST)},
		{Method: http.MethodPost, Path: "/email/password/reset/confirm", Group: RoutePassword, Handler: http.HandlerFunc(s.handleEmailPasswordResetConfirmPOST)},
		{Method: http.MethodPost, Path: "/email/password/reset/confirm-link", Group: RoutePassword, Handler: http.HandlerFunc(s.handleEmailPasswordResetConfirmLinkPOST)},
		{Method: http.MethodPost, Path: "/phone/password/reset/request", Group: RoutePassword, Handler: http.HandlerFunc(s.handlePhonePasswordResetRequestPOST)},
		{Method: http.MethodPost, Path: "/phone/password/reset/confirm", Group: RoutePassword, Handler: http.HandlerFunc(s.handlePhonePasswordResetConfirmPOST)},
		{Method: http.MethodPost, Path: "/phone/password/reset/confirm-link", Group: RoutePassword, Handler: http.HandlerFunc(s.handleEmailPasswordResetConfirmLinkPOST)},

		{Method: http.MethodPost, Path: "/register", Group: RouteRegister, Handler: http.HandlerFunc(s.handleRegisterUnifiedPOST)},
		{Method: http.MethodGet, Path: "/register/availability", Group: RouteRegister, Handler: http.HandlerFunc(s.handleRegisterAvailabilityGET)},
		{Method: http.MethodPost, Path: "/register/resend-email", Group: RouteRegister, Handler: http.HandlerFunc(s.handlePendingRegistrationResendPOST)},
		{Method: http.MethodPost, Path: "/register/resend-phone", Group: RouteRegister, Handler: http.HandlerFunc(s.handlePhoneRegisterResendPOST)},
		{Method: http.MethodPost, Path: "/register/abandon", Group: RouteRegister, Handler: http.HandlerFunc(s.handlePendingRegistrationAbandonPOST)},

		{Method: http.MethodGet, Path: "/namespaces/{slug}", Group: RouteOwners, Handler: http.HandlerFunc(s.handleOwnerNamespaceInfoGET)},

		{Method: http.MethodPost, Path: "/email/verify/request", Group: RouteEmailVerification, Handler: http.HandlerFunc(s.handleEmailVerifyRequestPOST)},
		{Method: http.MethodPost, Path: "/email/verify/confirm", Group: RouteEmailVerification, Handler: http.HandlerFunc(s.handleEmailVerifyConfirmPOST)},
		{Method: http.MethodPost, Path: "/email/verify/confirm-link", Group: RouteEmailVerification, Handler: http.HandlerFunc(s.handleEmailVerifyConfirmLinkPOST)},

		{Method: http.MethodPost, Path: "/phone/verify/request", Group: RoutePhoneVerification, Handler: http.HandlerFunc(s.handlePhoneVerifyRequestPOST)},
		{Method: http.MethodPost, Path: "/phone/verify/confirm", Group: RoutePhoneVerification, Handler: http.HandlerFunc(s.handlePhoneVerifyConfirmPOST)},
		{Method: http.MethodPost, Path: "/phone/verify/confirm-link", Group: RoutePhoneVerification, Handler: http.HandlerFunc(s.handlePhoneVerifyConfirmLinkPOST)},

		{Method: http.MethodPost, Path: "/user/password", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserPasswordPOST))},
		{Method: http.MethodGet, Path: "/user/sessions", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserSessionsGET))},
		{Method: http.MethodDelete, Path: "/user/sessions/{id}", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserSessionDELETE))},
		{Method: http.MethodDelete, Path: "/user/sessions", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserSessionsDELETE))},
		{Method: http.MethodGet, Path: "/user/me", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserMeGET))},
		{Method: http.MethodGet, Path: "/me/bootstrap", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserBootstrapGET))},
		{Method: http.MethodPatch, Path: "/user/username", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserUsernamePATCH))},
		{Method: http.MethodPatch, Path: "/user/preferred-locale", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserPreferredLocalePATCH))},
		{Method: http.MethodPost, Path: "/user/email/change/request", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserEmailChangeRequestPOST))},
		{Method: http.MethodPost, Path: "/user/email/change/confirm", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserEmailChangeConfirmPOST))},
		{Method: http.MethodPost, Path: "/user/email/change/resend", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserEmailChangeResendPOST))},
		{Method: http.MethodPost, Path: "/user/email/change/cancel", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserEmailChangeCancelPOST))},
		{Method: http.MethodPost, Path: "/user/phone/change/request", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserPhoneChangeRequestPOST))},
		{Method: http.MethodPost, Path: "/user/phone/change/confirm", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserPhoneChangeConfirmPOST))},
		{Method: http.MethodPost, Path: "/user/phone/change/resend", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserPhoneChangeResendPOST))},
		{Method: http.MethodPost, Path: "/user/phone/change/cancel", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserPhoneChangeCancelPOST))},
		{Method: http.MethodPatch, Path: "/user/biography", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserBiographyPATCH))},
		{Method: http.MethodDelete, Path: "/user", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserDeleteDELETE))},
		{Method: http.MethodDelete, Path: "/user/providers/{provider}", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserUnlinkProviderDELETE))},

		{Method: http.MethodPost, Path: "/oidc/{provider}/link/start", Group: RouteAccountOIDCLinking, Handler: required(http.HandlerFunc(s.handleOIDCLinkStartPOST))},
		{Method: http.MethodPost, Path: "/oidc/{provider}/reauth/start", Group: RouteAccountOIDCLinking, Handler: required(http.HandlerFunc(s.handleOIDCReauthStartPOST))},

		{Method: http.MethodGet, Path: "/user/2fa", Group: RouteTwoFactor, Handler: required(http.HandlerFunc(s.handleUser2FAStatusGET))},
		{Method: http.MethodPost, Path: "/user/2fa/start-phone", Group: RouteTwoFactor, Handler: required(http.HandlerFunc(s.handleUser2FAStartPhonePOST))},
		{Method: http.MethodPost, Path: "/user/2fa/enable", Group: RouteTwoFactor, Handler: required(http.HandlerFunc(s.handleUser2FAEnablePOST))},
		{Method: http.MethodPost, Path: "/user/2fa/disable", Group: RouteTwoFactor, Handler: required(http.HandlerFunc(s.handleUser2FADisablePOST))},
		{Method: http.MethodPost, Path: "/user/2fa/regenerate-codes", Group: RouteTwoFactor, Handler: required(http.HandlerFunc(s.handleUser2FARegenerateCodesPOST))},
		{Method: http.MethodPost, Path: "/2fa/verify", Group: RouteTwoFactor, Handler: http.HandlerFunc(s.handleUser2FAVerifyPOST)},

		{Method: http.MethodPost, Path: "/solana/challenge", Group: RouteSolana, Handler: http.HandlerFunc(s.handleSolanaChallengePOST)},
		{Method: http.MethodPost, Path: "/solana/login", Group: RouteSolana, Handler: http.HandlerFunc(s.handleSolanaLoginPOST)},
		{Method: http.MethodPost, Path: "/solana/link", Group: RouteSolana, Handler: required(http.HandlerFunc(s.handleSolanaLinkPOST))},

		// Intrinsic user-admin directory (#111: org/platform RBAC removed). These
		// operate on the USER identity surface and are kept as part of authkit's
		// intrinsic /admin/* surface. They are authenticated (required); the former
		// `platform:` permission gating was removed with the platform RBAC plane.
		{Method: http.MethodGet, Path: "/admin/users", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handleAdminUsersListGET))},
		{Method: http.MethodGet, Path: "/admin/users/deleted", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handleAdminDeletedUsersListGET))},
		{Method: http.MethodGet, Path: "/admin/users/{user_id}", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handleAdminUserGET))},
		{Method: http.MethodGet, Path: "/admin/users/{user_id}/signins", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handleAdminUserSigninsGET))},
		{Method: http.MethodPost, Path: "/admin/users/ban", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handleAdminUsersBanPOST))},
		{Method: http.MethodPost, Path: "/admin/users/unban", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handleAdminUsersUnbanPOST))},
		{Method: http.MethodPost, Path: "/admin/users/set-email", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handleAdminUsersSetEmailPOST))},
		{Method: http.MethodPost, Path: "/admin/users/set-username", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handleAdminUsersSetUsernamePOST))},
		{Method: http.MethodPost, Path: "/admin/users/set-password", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handleAdminUsersSetPasswordPOST))},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/sessions/revoke", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handleAdminUserSessionsRevokePOST))},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/password-reset", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handleAdminUserPasswordResetPOST))},
		{Method: http.MethodDelete, Path: "/admin/users/{user_id}", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handleAdminUserDeleteDELETE))},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/restore", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handleAdminUserRestorePOST))},
		// 404 sentinel for a removed path that an adjacent wildcard would capture.
		{Method: http.MethodPost, Path: "/admin/users/toggle-active", Group: RouteAdmin, Handler: notFoundHandler},

		// Remote-application registry (#74, INBOUND accept side). A
		// remote_application is the federation PRINCIPAL (JWKS-credentialed) and a
		// pure ORG-NESTED sub-resource, exactly like api-keys (#95): the owning
		// org is in the PATH and management gates in-handler on
		// org:remote_applications:{create,update,delete}. Every issuer is org-owned
		// (org_id NOT NULL); there is no flat/global route and no global-admin.
		{Method: http.MethodPost, Path: "/orgs/{org}/remote-applications", Group: RouteOrgIssuers, Handler: required(http.HandlerFunc(s.handleRemoteApplicationRegisterPOST))},
		{Method: http.MethodDelete, Path: "/orgs/{org}/remote-applications/{slug}", Group: RouteOrgIssuers, Handler: required(http.HandlerFunc(s.handleRemoteApplicationDeleteDELETE))},
		// A remote_application's org memberships (assigned via the SAME role
		// machinery as users); {org} is the issuer's owning org.
		{Method: http.MethodPost, Path: "/orgs/{org}/remote-applications/{slug}/memberships", Group: RouteOrgIssuers, Handler: required(http.HandlerFunc(s.handleRemoteApplicationMembershipPOST))},
		{Method: http.MethodDelete, Path: "/orgs/{org}/remote-applications/{slug}/memberships", Group: RouteOrgIssuers, Handler: required(http.HandlerFunc(s.handleRemoteApplicationMembershipDELETE))},
		// Attribute definition registry (#75) — the federation token-CONTRACT
		// layer, NOT org management: the write is self-authored by the
		// remote_application and the read resolves a token reference for ANY
		// authenticated platform (no org context). Addressed by issuer {slug}
		// globally, so these stay flat (not org-nested).
		{Method: http.MethodPost, Path: "/remote-applications/{slug}/attribute-defs", Group: RouteOrgIssuers, Handler: required(http.HandlerFunc(s.handleAttributeDefPutPOST))},
		{Method: http.MethodGet, Path: "/remote-applications/{slug}/attribute-defs", Group: RouteOrgIssuers, Handler: required(http.HandlerFunc(s.handleAttributeDefGET))},
	}

	// #111: the org/platform RBAC HTTP surface (members, roles, invites, org
	// permissions, the org-nested api-keys mount) was removed. The
	// permission-group route generator re-homes group management; the api-key and
	// remote-application handlers survive in their own files to be re-nested there.

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

// OIDCBrowserRoutes returns browser redirect routes with no mount prefix.
func (s *Service) OIDCBrowserRoutes(groups ...RouteGroup) []RouteSpec {
	if s == nil || s.svc == nil {
		return nil
	}
	selected := routeGroupSet(groups)
	lang := func(h http.Handler) http.Handler { return LanguageMiddleware(s.langCfg)(h) }
	routes := []RouteSpec{
		{Method: http.MethodGet, Path: "/{provider}/login", Group: RouteOIDCBrowser, Handler: http.HandlerFunc(s.handleOIDCLoginGET)},
		{Method: http.MethodGet, Path: "/{provider}/callback", Group: RouteOIDCBrowser, Handler: http.HandlerFunc(s.handleOIDCCallbackGET)},
		{Method: http.MethodGet, Path: "/{provider}/reauth/callback", Group: RouteOIDCBrowser, Handler: http.HandlerFunc(s.handleOIDCCallbackGET)},
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
