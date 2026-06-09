package authhttp

import (
	"net/http"
	"strings"
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
	RouteTenants            RouteGroup = "tenants"
	RouteUser               RouteGroup = "user"
	RouteAccountOIDCLinking RouteGroup = "account_oidc_linking"
	RouteTwoFactor          RouteGroup = "two_factor"
	RouteSolana             RouteGroup = "solana"
	RouteAdmin              RouteGroup = "admin"
	RouteOIDCBrowser        RouteGroup = "oidc_browser"
	// RouteTenantIssuers exposes the inbound accept-side tenant-issuer registry
	// routes (the home for what tensorhub previously exposed as
	// `/api/v1/platform/issuers`).
	RouteTenantIssuers RouteGroup = "federation"
)

// RouteSpec is a concrete, prefix-neutral route with its AuthKit handler
// attached. Path parameters use net/http ServeMux syntax, e.g.
// "/owners/{slug}".
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
	admin := func(h http.Handler) http.Handler { return required(RequireAdmin(s.svc.Postgres())(h)) }
	lang := func(h http.Handler) http.Handler { return LanguageMiddleware(s.langCfg)(h) }
	notFoundHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		notFound(w, "not_found")
	})

	routes := []RouteSpec{
		{Method: http.MethodPost, Path: "/token", Group: RouteCore, Handler: http.HandlerFunc(s.handleAuthTokenPOST)},
		{Method: http.MethodGet, Path: "/providers", Group: RouteCore, Handler: http.HandlerFunc(s.handleProvidersGET)},
		{Method: http.MethodPost, Path: "/sessions/current", Group: RouteCore, Handler: http.HandlerFunc(s.handleAuthSessionsCurrentPOST)},
		{Method: http.MethodDelete, Path: "/logout", Group: RouteCore, Handler: required(http.HandlerFunc(s.handleLogoutDELETE))},
		{Method: http.MethodPost, Path: "/reauth/password", Group: RoutePassword, Handler: required(http.HandlerFunc(s.handlePasswordReauthPOST))},

		{Method: http.MethodPost, Path: "/password/login", Group: RoutePassword, Handler: http.HandlerFunc(s.handlePasswordLoginPOST)},
		{Method: http.MethodPost, Path: "/email/password/reset/request", Group: RoutePassword, Handler: http.HandlerFunc(s.handleEmailPasswordResetRequestPOST)},
		{Method: http.MethodPost, Path: "/email/password/reset/confirm", Group: RoutePassword, Handler: http.HandlerFunc(s.handleEmailPasswordResetConfirmPOST)},
		{Method: http.MethodPost, Path: "/email/password/reset/confirm-link", Group: RoutePassword, Handler: http.HandlerFunc(s.handleEmailPasswordResetConfirmLinkPOST)},
		{Method: http.MethodPost, Path: "/phone/password/reset/request", Group: RoutePassword, Handler: http.HandlerFunc(s.handlePhonePasswordResetRequestPOST)},
		{Method: http.MethodPost, Path: "/phone/password/reset/confirm", Group: RoutePassword, Handler: http.HandlerFunc(s.handlePhonePasswordResetConfirmPOST)},

		{Method: http.MethodPost, Path: "/register", Group: RouteRegister, Handler: http.HandlerFunc(s.handleRegisterUnifiedPOST)},
		{Method: http.MethodGet, Path: "/register/availability", Group: RouteRegister, Handler: http.HandlerFunc(s.handleRegisterAvailabilityGET)},
		{Method: http.MethodPost, Path: "/register/resend-email", Group: RouteRegister, Handler: http.HandlerFunc(s.handlePendingRegistrationResendPOST)},
		{Method: http.MethodPost, Path: "/register/resend-phone", Group: RouteRegister, Handler: http.HandlerFunc(s.handlePhoneRegisterResendPOST)},
		{Method: http.MethodPost, Path: "/register/abandon", Group: RouteRegister, Handler: http.HandlerFunc(s.handlePendingRegistrationAbandonPOST)},

		{Method: http.MethodGet, Path: "/owners/{slug}", Group: RouteOwners, Handler: http.HandlerFunc(s.handleOwnerNamespaceInfoGET)},

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
		{Method: http.MethodGet, Path: "/user/bootstrap", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserBootstrapGET))},
		{Method: http.MethodPatch, Path: "/user/username", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserUsernamePATCH))},
		{Method: http.MethodPatch, Path: "/user/preferred-locale", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserPreferredLocalePATCH))},
		{Method: http.MethodPost, Path: "/user/email/change/request", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserEmailChangeRequestPOST))},
		{Method: http.MethodPost, Path: "/user/email/change/confirm", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserEmailChangeConfirmPOST))},
		{Method: http.MethodPost, Path: "/user/email/change/resend", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserEmailChangeResendPOST))},
		{Method: http.MethodPost, Path: "/user/phone/change/request", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserPhoneChangeRequestPOST))},
		{Method: http.MethodPost, Path: "/user/phone/change/confirm", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserPhoneChangeConfirmPOST))},
		{Method: http.MethodPost, Path: "/user/phone/change/resend", Group: RouteUser, Handler: required(http.HandlerFunc(s.handleUserPhoneChangeResendPOST))},
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

		{Method: http.MethodPost, Path: "/admin/roles/grant", Group: RouteAdmin, Handler: admin(http.HandlerFunc(s.handleAdminRolesGrantPOST))},
		{Method: http.MethodPost, Path: "/admin/roles/revoke", Group: RouteAdmin, Handler: admin(http.HandlerFunc(s.handleAdminRolesRevokePOST))},
		{Method: http.MethodGet, Path: "/admin/users", Group: RouteAdmin, Handler: admin(http.HandlerFunc(s.handleAdminUsersListGET))},
		{Method: http.MethodGet, Path: "/admin/users/{user_id}", Group: RouteAdmin, Handler: admin(http.HandlerFunc(s.handleAdminUserGET))},
		{Method: http.MethodPost, Path: "/admin/users/ban", Group: RouteAdmin, Handler: admin(http.HandlerFunc(s.handleAdminUsersBanPOST))},
		{Method: http.MethodPost, Path: "/admin/users/unban", Group: RouteAdmin, Handler: admin(http.HandlerFunc(s.handleAdminUsersUnbanPOST))},
		{Method: http.MethodPost, Path: "/admin/users/set-email", Group: RouteAdmin, Handler: admin(http.HandlerFunc(s.handleAdminUsersSetEmailPOST))},
		{Method: http.MethodPost, Path: "/admin/users/set-username", Group: RouteAdmin, Handler: admin(http.HandlerFunc(s.handleAdminUsersSetUsernamePOST))},
		{Method: http.MethodPost, Path: "/admin/users/set-password", Group: RouteAdmin, Handler: admin(http.HandlerFunc(s.handleAdminUsersSetPasswordPOST))},
		{Method: http.MethodPost, Path: "/admin/users/toggle-active", Group: RouteAdmin, Handler: notFoundHandler},
		{Method: http.MethodDelete, Path: "/admin/users/{user_id}", Group: RouteAdmin, Handler: admin(http.HandlerFunc(s.handleAdminUserDeleteDELETE))},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/restore", Group: RouteAdmin, Handler: admin(http.HandlerFunc(s.handleAdminUserRestorePOST))},
		{Method: http.MethodGet, Path: "/admin/users/deleted", Group: RouteAdmin, Handler: admin(http.HandlerFunc(s.handleAdminDeletedUsersListGET))},
		{Method: http.MethodGet, Path: "/admin/users/{user_id}/signins", Group: RouteAdmin, Handler: admin(http.HandlerFunc(s.handleAdminUserSigninsGET))},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/sessions/revoke", Group: RouteAdmin, Handler: admin(http.HandlerFunc(s.handleAdminUserSessionsRevokePOST))},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/password-reset", Group: RouteAdmin, Handler: admin(http.HandlerFunc(s.handleAdminUserPasswordResetPOST))},
		{Method: http.MethodPost, Path: "/admin/accounts/restrict", Group: RouteAdmin, Handler: admin(http.HandlerFunc(s.handleAdminAccountsRestrictPOST))},
		{Method: http.MethodPost, Path: "/admin/accounts/unrestrict", Group: RouteAdmin, Handler: admin(http.HandlerFunc(s.handleAdminAccountsUnrestrictPOST))},
		{Method: http.MethodPost, Path: "/admin/account/park", Group: RouteAdmin, Handler: admin(http.HandlerFunc(s.handleAdminAccountParkPOST))},
		{Method: http.MethodPost, Path: "/admin/account/claim", Group: RouteAdmin, Handler: admin(http.HandlerFunc(s.handleAdminAccountClaimPOST))},
		{Method: http.MethodPost, Path: "/admin/tenant/park", Group: RouteAdmin, Handler: notFoundHandler},
		{Method: http.MethodPost, Path: "/admin/tenant/claim", Group: RouteAdmin, Handler: notFoundHandler},

		// Federated-tenant issuer registry (INBOUND accept side). Registration +
		// deletion authorize on tenant owner/admin inside the handler (so they only
		// need `required`, not the global-admin RequireAdmin gate). Listing is
		// global-admin only for operator visibility.
		{Method: http.MethodPost, Path: "/tenant-issuers", Group: RouteTenantIssuers, Handler: required(http.HandlerFunc(s.handleTenantIssuerRegisterPOST))},
		{Method: http.MethodDelete, Path: "/tenant-issuers", Group: RouteTenantIssuers, Handler: required(http.HandlerFunc(s.handleTenantIssuerDeleteDELETE))},
		{Method: http.MethodGet, Path: "/tenant-issuers", Group: RouteTenantIssuers, Handler: admin(http.HandlerFunc(s.handleTenantIssuersListGET))},
	}

	// When public tenant onboarding/management is disabled, wrap the mutating
	// tenant-facing routes with a stable tenant_management_disabled deny handler.
	// Read-only tenant routes (listing, lookup, role/permission reads,
	// introspection) and the tenant-scoped token route stay available so existing
	// members can still authenticate and inspect their tenants. Embedded
	// bootstrap/admin core APIs are unaffected (they never traverse these HTTP
	// handlers).
	orgMgmt := func(method, path string, h http.Handler) http.Handler {
		if !s.publicTenantManagementDisabled() {
			return h
		}
		if !isPublicTenantManagementRoute(method, path) {
			return h
		}
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			tenantManagementDisabled(w)
		})
	}

	// (issue 60) Tenant routes are always registered under the RouteTenants group;
	// the host decides exposure by mounting (or not) that group, and mutating
	// routes are gated by TenantRegistrationMode in their handlers. No tenant-mode
	// gate.
	{
		routes = append(routes,
			RouteSpec{Method: http.MethodPost, Path: "/token/tenant", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleAuthTokenOrgPOST))},
			RouteSpec{Method: http.MethodGet, Path: "/tenants", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleOrgsListGET))},
			RouteSpec{Method: http.MethodPost, Path: "/tenants", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleOrgsCreatePOST))},
			RouteSpec{Method: http.MethodGet, Path: "/tenants/{tenant}", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleOrgsGetGET))},
			RouteSpec{Method: http.MethodPost, Path: "/tenants/{tenant}/rename", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleOrgsRenamePOST))},
			RouteSpec{Method: http.MethodGet, Path: "/tenants/{tenant}/members", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleOrgMembersGET))},
			RouteSpec{Method: http.MethodPost, Path: "/tenants/{tenant}/members", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleOrgMembersPOST))},
			RouteSpec{Method: http.MethodDelete, Path: "/tenants/{tenant}/members/{user_id}", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleOrgMembersDELETE))},
			RouteSpec{Method: http.MethodGet, Path: "/tenants/{tenant}/invites", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleTenantInvitesGET))},
			RouteSpec{Method: http.MethodPost, Path: "/tenants/{tenant}/invites", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleTenantInvitesPOST))},
			RouteSpec{Method: http.MethodPost, Path: "/tenants/{tenant}/invites/{invite_id}/revoke", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleTenantInviteRevokePOST))},
			RouteSpec{Method: http.MethodGet, Path: "/me/invites", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleUserInvitesGET))},
			RouteSpec{Method: http.MethodPost, Path: "/me/invites/{invite_id}/accept", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleTenantInviteAcceptPOST))},
			RouteSpec{Method: http.MethodPost, Path: "/me/invites/{invite_id}/decline", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleTenantInviteDeclinePOST))},
			RouteSpec{Method: http.MethodGet, Path: "/tenants/{tenant}/roles", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleTenantRolesGET))},
			RouteSpec{Method: http.MethodGet, Path: "/tenants/{tenant}/roles/{role}", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleTenantRoleGET))},
			RouteSpec{Method: http.MethodPut, Path: "/tenants/{tenant}/roles/{role}", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleTenantRolePUT))},
			RouteSpec{Method: http.MethodDelete, Path: "/tenants/{tenant}/roles/{role}", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleTenantRolesDELETE))},
			RouteSpec{Method: http.MethodPost, Path: "/tenants/{tenant}/service-tokens", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleServiceTokensPOST))},
			RouteSpec{Method: http.MethodGet, Path: "/tenants/{tenant}/service-tokens", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleServiceTokensGET))},
			RouteSpec{Method: http.MethodDelete, Path: "/tenants/{tenant}/service-tokens/{token_id}", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleServiceTokenDELETE))},
			RouteSpec{Method: http.MethodGet, Path: "/permissions", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handlePermissionCatalogGET))},
			RouteSpec{Method: http.MethodGet, Path: "/tenants/{tenant}/members/{user_id}/permissions", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleOrgMemberPermissionsGET))},
			RouteSpec{Method: http.MethodGet, Path: "/tenants/{tenant}/members/{user_id}/roles", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleOrgMemberRolesGET))},
			RouteSpec{Method: http.MethodPost, Path: "/tenants/{tenant}/members/{user_id}/roles", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleOrgMemberRolesPOST))},
			RouteSpec{Method: http.MethodDelete, Path: "/tenants/{tenant}/members/{user_id}/roles", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleOrgMemberRolesDELETE))},
			// Introspection (#46 follow-up): self (/me) + permission check.
			RouteSpec{Method: http.MethodGet, Path: "/tenants/{tenant}/me", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleOrgMeGET))},
			RouteSpec{Method: http.MethodPost, Path: "/tenants/{tenant}/permissions/check", Group: RouteTenants, Handler: required(http.HandlerFunc(s.handleOrgPermissionCheckPOST))},
		)
	}

	out := make([]RouteSpec, 0, len(routes))
	for _, route := range routes {
		if !selected(route.Group) {
			continue
		}
		if route.Group == RouteTenants {
			route.Handler = orgMgmt(route.Method, route.Path, route.Handler)
		}
		route.Handler = lang(route.Handler)
		out = append(out, route)
	}
	return out
}

// isPublicTenantManagementRoute reports whether (method, path) is a public
// tenant-facing onboarding/management route gated by TenantRegistrationMode.
// These are the mutating tenant routes (creation, rename, invites, member changes,
// role changes, service token management) plus invite acceptance/decline. Read-only tenant
// routes and the tenant-scoped token route are intentionally excluded so existing
// members can still authenticate and inspect their tenants.
func isPublicTenantManagementRoute(method, path string) bool {
	switch method {
	case http.MethodGet:
		// All tenant reads stay available (listings, lookups, role/permission
		// reads, introspection).
		return false
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		// The tenant-scoped token exchange (`POST /token/tenant`) is authentication,
		// not tenant management — keep it available for existing members.
		if method == http.MethodPost && path == "/token/tenant" {
			return false
		}
		return strings.HasPrefix(path, "/tenants") || strings.HasPrefix(path, "/me/invites")
	default:
		return false
	}
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
