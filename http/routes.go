package authhttp

import (
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
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
	// platformGated gates a /admin/* route on a specific Layer-2 `platform:`
	// permission (#95) — the platform RBAC plane is the SOLE admin authority, in
	// place of the legacy global-admin gate. Authenticated (required) first, then
	// the in-handler platform-permission check; no global-admin bypass.
	platformGated := func(perm string, h http.Handler) http.Handler {
		return required(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				unauthorized(w, "unauthorized")
				return
			}
			if !s.requirePlatformPermission(w, r, claims, perm) {
				return
			}
			h.ServeHTTP(w, r)
		}))
	}
	lang := func(h http.Handler) http.Handler { return LanguageMiddleware(s.langCfg)(h) }
	// notFoundHandler explicitly 404s a removed path that an adjacent wildcard
	// route would otherwise capture (e.g. POST /admin/users/toggle-active would
	// match GET /admin/users/{user_id} → 405). These are 404 sentinels.
	notFoundHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		notFound(w, "not_found")
	})

	routes := []RouteSpec{
		{Method: http.MethodPost, Path: "/token", Group: RouteCore, Handler: http.HandlerFunc(s.handleAuthTokenPOST)},
		{Method: http.MethodGet, Path: "/identity-providers", Group: RouteCore, Handler: http.HandlerFunc(s.handleProvidersGET)},
		{Method: http.MethodPost, Path: "/sessions/current", Group: RouteCore, Handler: http.HandlerFunc(s.handleAuthSessionsCurrentPOST)},
		{Method: http.MethodDelete, Path: "/logout", Group: RouteCore, Handler: required(http.HandlerFunc(s.handleLogoutDELETE))},
		// "What are my permissions" introspection (#76 amendment): the caller's
		// GRANTED ceiling + identity, for any programmatic principal.
		{Method: http.MethodGet, Path: "/me/permissions", Group: RouteCore, Handler: required(http.HandlerFunc(s.handleMePermissionsGET))},
		// Caller's OWN effective Layer-2 platform permissions (#95 self introspection).
		{Method: http.MethodGet, Path: "/me/platform-permissions", Group: RouteCore, Handler: required(http.HandlerFunc(s.handleMePlatformPermissionsGET))},
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

		// Layer-2 Platform RBAC admin API (#95). Authenticated; each handler gates
		// IN-HANDLER on the specific `platform:` permission (requirePlatformPermission)
		// — NOT the legacy RequireAdmin gate. Define platform roles, then grant them
		// to users (minting platform-admins). The first super-admin (`platform:*`) is
		// seeded out-of-band (bootstrap/manifest), like an org's first owner.
		{Method: http.MethodGet, Path: "/admin/platform-roles", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handlePlatformRolesGET))},
		{Method: http.MethodGet, Path: "/admin/platform-roles/{role}", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handlePlatformRoleGET))},
		{Method: http.MethodPut, Path: "/admin/platform-roles/{role}", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handlePlatformRolePUT))},
		{Method: http.MethodDelete, Path: "/admin/platform-roles/{role}", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handlePlatformRoleDELETE))},
		{Method: http.MethodGet, Path: "/admin/platform-roles/{role}/members", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handlePlatformRoleMembersGET))},
		{Method: http.MethodPost, Path: "/admin/platform-roles/{role}/grant", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handlePlatformRoleGrantPOST))},
		{Method: http.MethodPost, Path: "/admin/platform-roles/{role}/revoke", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handlePlatformRoleRevokePOST))},
		// Org-admin surface (#95, platform:orgs:*). Administer ANY org as an
		// ENTITY — directory, soft-delete/restore, and the anti-takeover `recover`
		// reset. Entity-level only; each handler gates on the specific platform:orgs perm.
		{Method: http.MethodGet, Path: "/admin/orgs", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handleAdminOrgsListGET))},
		{Method: http.MethodGet, Path: "/admin/orgs/{id}", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handleAdminOrgGET))},
		{Method: http.MethodDelete, Path: "/admin/orgs/{id}", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handleAdminOrgDELETE))},
		{Method: http.MethodPost, Path: "/admin/orgs/{id}/restore", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handleAdminOrgRestorePOST))},
		{Method: http.MethodPost, Path: "/admin/orgs/{id}/recover", Group: RouteAdmin, Handler: required(http.HandlerFunc(s.handleAdminOrgRecoverPOST))},
		// User-admin directory (#95): hard-cut to platform RBAC — gated on
		// platform:users:* (read/ban/update/delete). The legacy global-admin gate
		// is GONE; the platform plane is the sole admin authority.
		{Method: http.MethodGet, Path: "/admin/users", Group: RouteAdmin, Handler: platformGated(core.PermPlatformUsersRead, http.HandlerFunc(s.handleAdminUsersListGET))},
		{Method: http.MethodGet, Path: "/admin/users/deleted", Group: RouteAdmin, Handler: platformGated(core.PermPlatformUsersRead, http.HandlerFunc(s.handleAdminDeletedUsersListGET))},
		{Method: http.MethodGet, Path: "/admin/users/{user_id}", Group: RouteAdmin, Handler: platformGated(core.PermPlatformUsersRead, http.HandlerFunc(s.handleAdminUserGET))},
		{Method: http.MethodGet, Path: "/admin/users/{user_id}/signins", Group: RouteAdmin, Handler: platformGated(core.PermPlatformUsersRead, http.HandlerFunc(s.handleAdminUserSigninsGET))},
		{Method: http.MethodPost, Path: "/admin/users/ban", Group: RouteAdmin, Handler: platformGated(core.PermPlatformUsersBan, http.HandlerFunc(s.handleAdminUsersBanPOST))},
		{Method: http.MethodPost, Path: "/admin/users/unban", Group: RouteAdmin, Handler: platformGated(core.PermPlatformUsersBan, http.HandlerFunc(s.handleAdminUsersUnbanPOST))},
		{Method: http.MethodPost, Path: "/admin/users/set-email", Group: RouteAdmin, Handler: platformGated(core.PermPlatformUsersUpdate, http.HandlerFunc(s.handleAdminUsersSetEmailPOST))},
		{Method: http.MethodPost, Path: "/admin/users/set-username", Group: RouteAdmin, Handler: platformGated(core.PermPlatformUsersUpdate, http.HandlerFunc(s.handleAdminUsersSetUsernamePOST))},
		{Method: http.MethodPost, Path: "/admin/users/set-password", Group: RouteAdmin, Handler: platformGated(core.PermPlatformUsersUpdate, http.HandlerFunc(s.handleAdminUsersSetPasswordPOST))},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/sessions/revoke", Group: RouteAdmin, Handler: platformGated(core.PermPlatformUsersUpdate, http.HandlerFunc(s.handleAdminUserSessionsRevokePOST))},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/password-reset", Group: RouteAdmin, Handler: platformGated(core.PermPlatformUsersUpdate, http.HandlerFunc(s.handleAdminUserPasswordResetPOST))},
		{Method: http.MethodDelete, Path: "/admin/users/{user_id}", Group: RouteAdmin, Handler: platformGated(core.PermPlatformUsersDelete, http.HandlerFunc(s.handleAdminUserDeleteDELETE))},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/restore", Group: RouteAdmin, Handler: platformGated(core.PermPlatformUsersDelete, http.HandlerFunc(s.handleAdminUserRestorePOST))},
		// Reserved-name slug lifecycle (#95): gated on platform:orgs:reserved-names.
		{Method: http.MethodPost, Path: "/admin/accounts/restrict", Group: RouteAdmin, Handler: platformGated(core.PermPlatformOrgsReservedNames, http.HandlerFunc(s.handleAdminAccountsRestrictPOST))},
		{Method: http.MethodPost, Path: "/admin/accounts/unrestrict", Group: RouteAdmin, Handler: platformGated(core.PermPlatformOrgsReservedNames, http.HandlerFunc(s.handleAdminAccountsUnrestrictPOST))},
		{Method: http.MethodPost, Path: "/admin/account/park", Group: RouteAdmin, Handler: platformGated(core.PermPlatformOrgsReservedNames, http.HandlerFunc(s.handleAdminAccountParkPOST))},
		{Method: http.MethodPost, Path: "/admin/account/claim", Group: RouteAdmin, Handler: platformGated(core.PermPlatformOrgsReservedNames, http.HandlerFunc(s.handleAdminAccountClaimPOST))},
		// 404 sentinels for removed routes that adjacent wildcards would capture.
		{Method: http.MethodPost, Path: "/admin/users/toggle-active", Group: RouteAdmin, Handler: notFoundHandler},
		{Method: http.MethodPost, Path: "/admin/org/park", Group: RouteAdmin, Handler: notFoundHandler},
		{Method: http.MethodPost, Path: "/admin/org/claim", Group: RouteAdmin, Handler: notFoundHandler},

		// Remote-application registry (#74, INBOUND accept side). A
		// remote_application is the federation PRINCIPAL (JWKS-credentialed).
		// Register/delete authorize on the principal owner inside the handler;
		// listing is global-admin only for operator visibility.
		{Method: http.MethodPost, Path: "/remote-applications", Group: RouteOrgIssuers, Handler: required(http.HandlerFunc(s.handleRemoteApplicationRegisterPOST))},
		{Method: http.MethodDelete, Path: "/remote-applications", Group: RouteOrgIssuers, Handler: required(http.HandlerFunc(s.handleRemoteApplicationDeleteDELETE))},
		// A remote_application's org memberships (assigned via the SAME role
		// machinery as users).
		{Method: http.MethodPost, Path: "/remote-applications/{slug}/memberships", Group: RouteOrgIssuers, Handler: required(http.HandlerFunc(s.handleRemoteApplicationMembershipPOST))},
		{Method: http.MethodDelete, Path: "/remote-applications/{slug}/memberships", Group: RouteOrgIssuers, Handler: required(http.HandlerFunc(s.handleRemoteApplicationMembershipDELETE))},
		// Attribute definition registry (#75): write side (remote_app authors)
		// + read/resolve side (any platform resolving a token reference).
		{Method: http.MethodPost, Path: "/remote-applications/{slug}/attribute-defs", Group: RouteOrgIssuers, Handler: required(http.HandlerFunc(s.handleAttributeDefPutPOST))},
		{Method: http.MethodGet, Path: "/remote-applications/{slug}/attribute-defs", Group: RouteOrgIssuers, Handler: required(http.HandlerFunc(s.handleAttributeDefGET))},
	}

	// When public org onboarding/management is disabled, wrap the mutating
	// org-facing routes with a stable org_management_disabled deny handler.
	// Read-only org routes stay available so existing members can inspect their
	// orgs. Embedded bootstrap/admin core APIs are unaffected (they never
	// traverse these HTTP handlers).
	orgMgmt := func(method, path string, h http.Handler) http.Handler {
		if !s.publicOrgManagementDisabled() {
			return h
		}
		if !isPublicOrgManagementRoute(method, path) {
			return h
		}
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			orgManagementDisabled(w)
		})
	}

	// (issue 60) Org routes are always registered under the RouteOrgs group;
	// the host decides exposure by mounting (or not) that group, and mutating
	// routes are gated by OrgRegistrationMode in their handlers. No org-mode
	// gate.
	{
		routes = append(routes,
			RouteSpec{Method: http.MethodGet, Path: "/me/orgs", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleOrgsListGET))},
			RouteSpec{Method: http.MethodPost, Path: "/orgs", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleOrgsCreatePOST))},
			RouteSpec{Method: http.MethodGet, Path: "/orgs/{org}", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleOrgsGetGET))},
			RouteSpec{Method: http.MethodPost, Path: "/orgs/{org}/rename", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleOrgsRenamePOST))},
			RouteSpec{Method: http.MethodGet, Path: "/orgs/{org}/members", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleOrgMembersGET))},
			RouteSpec{Method: http.MethodPost, Path: "/orgs/{org}/members", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleOrgMembersPOST))},
			RouteSpec{Method: http.MethodDelete, Path: "/orgs/{org}/members/{user_id}", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleOrgMembersDELETE))},
			RouteSpec{Method: http.MethodGet, Path: "/orgs/{org}/invites", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleOrgInvitesGET))},
			RouteSpec{Method: http.MethodPost, Path: "/orgs/{org}/invites", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleOrgInvitesPOST))},
			RouteSpec{Method: http.MethodPost, Path: "/orgs/{org}/invites/{invite_id}/revoke", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleOrgInviteRevokePOST))},
			RouteSpec{Method: http.MethodGet, Path: "/me/org-invites", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleUserInvitesGET))},
			RouteSpec{Method: http.MethodPost, Path: "/me/org-invites/{invite_id}/accept", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleOrgInviteAcceptPOST))},
			RouteSpec{Method: http.MethodPost, Path: "/me/org-invites/{invite_id}/decline", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleOrgInviteDeclinePOST))},
			RouteSpec{Method: http.MethodGet, Path: "/orgs/{org}/roles", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleOrgRolesGET))},
			RouteSpec{Method: http.MethodGet, Path: "/orgs/{org}/roles/{role}", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleOrgRoleGET))},
			RouteSpec{Method: http.MethodPut, Path: "/orgs/{org}/roles/{role}", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleOrgRolePUT))},
			RouteSpec{Method: http.MethodDelete, Path: "/orgs/{org}/roles/{role}", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleOrgRolesDELETE))},
			RouteSpec{Method: http.MethodPost, Path: "/orgs/{org}/api-keys", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleAPIKeysPOST))},
			RouteSpec{Method: http.MethodGet, Path: "/orgs/{org}/api-keys", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleAPIKeysGET))},
			RouteSpec{Method: http.MethodDelete, Path: "/orgs/{org}/api-keys/{token_id}", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleAPIKeyDELETE))},
			RouteSpec{Method: http.MethodGet, Path: "/permissions", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handlePermissionsGET))},
			RouteSpec{Method: http.MethodGet, Path: "/orgs/{org}/members/{user_id}/permissions", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleOrgMemberPermissionsGET))},
			RouteSpec{Method: http.MethodGet, Path: "/orgs/{org}/members/{user_id}/roles", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleOrgMemberRolesGET))},
			RouteSpec{Method: http.MethodPost, Path: "/orgs/{org}/members/{user_id}/roles", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleOrgMemberRolesPOST))},
			RouteSpec{Method: http.MethodDelete, Path: "/orgs/{org}/members/{user_id}/roles", Group: RouteOrgs, Handler: required(http.HandlerFunc(s.handleOrgMemberRolesDELETE))},
		)
	}

	out := make([]RouteSpec, 0, len(routes))
	for _, route := range routes {
		if !selected(route.Group) {
			continue
		}
		if route.Group == RouteOrgs {
			route.Handler = orgMgmt(route.Method, route.Path, route.Handler)
		}
		route.Handler = lang(route.Handler)
		out = append(out, route)
	}
	return out
}

// isPublicOrgManagementRoute reports whether (method, path) is a public
// org-facing onboarding/management route gated by OrgRegistrationMode.
// These are the mutating org routes (creation, rename, invites, member changes,
// role changes, API key management) plus invite acceptance/decline. Read-only org
// routes are intentionally excluded so existing members can inspect their orgs.
func isPublicOrgManagementRoute(method, path string) bool {
	switch method {
	case http.MethodGet:
		// All org reads stay available (listings, lookups, role/permission
		// reads, introspection).
		return false
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return strings.HasPrefix(path, "/orgs") || strings.HasPrefix(path, "/me/org-invites")
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
