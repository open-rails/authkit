package authhttp

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/verify"

	"github.com/open-rails/authkit/embedded"
)

// RouteGroup identifies a prefix-neutral AuthKit route capability. Host
// applications can mount all default groups or select only the capabilities
// they want to expose.
type RouteGroup string

const (
	RouteAuth RouteGroup = "auth"
	// RouteDeviceKeys is the refreshless native-client login surface: email
	// enrollment plus Ed25519 challenge authentication.
	RouteDeviceKeys       RouteGroup = "device_keys"
	RouteRegistration     RouteGroup = "registration"
	RouteAccount          RouteGroup = "account"
	RouteAdmin            RouteGroup = "admin"
	RoutePermissionGroups RouteGroup = "permission_groups"
	RouteBrowserOIDC      RouteGroup = "browser_oidc"
	// RouteApplications is the #264 application self-registration surface
	// (register / rotate / repoint). Mounted only when the host enables
	// Config.Applications.SelfRegistration.
	RouteApplications RouteGroup = "applications"
	// RouteDelegated is the #261 delegated-token mint surface
	// (POST /delegated/token). Mounted only when Config.Delegated declares an
	// audience allowlist.
	RouteDelegated RouteGroup = "delegated"
	// RouteDocuments is the #260 published signed-document surface
	// (GET|HEAD /.well-known/authkit/documents/{digest} — root-anchored like
	// JWKS, not under the API prefix). Mounted only when document providers
	// are wired via WithDocuments.
	RouteDocuments RouteGroup = "documents"
)

// RouteAuth is the authentication tier a route enforces before its handler
// runs (#328).
type RouteAuthTier string

const (
	AuthPublic     RouteAuthTier = "public"     // no principal
	AuthOptional   RouteAuthTier = "optional"   // principal used when present
	AuthRequired   RouteAuthTier = "required"   // valid principal
	AuthPermission RouteAuthTier = "permission" // valid principal holding RouteSpec.Permission
	AuthSigned     RouteAuthTier = "signed"     // per-message proof (domain fetch / JWS)
)

// RouteSpec is a concrete, prefix-neutral route with its AuthKit handler
// attached. Path parameters use net/http ServeMux syntax, e.g.
// "/namespaces/{slug}".
type RouteSpec struct {
	Method  string
	Path    string
	Group   RouteGroup
	Handler http.Handler
	// Auth is the tier the handler wrapper enforces before the handler runs;
	// Permission names the root/group permission for AuthPermission (#328).
	Auth       RouteAuthTier
	Permission string
	// Bucket is the per-IP rate-limit bucket APIRoutes applies in front of the
	// handler ("" = none). Per-identifier and branch-specific buckets stay in
	// the handler.
	Bucket string
	// MFAEnrollmentExempt marks a route as part of the 2FA enroll/challenge/
	// verify surface a forced-enrollment-gated user (verify.WithRequireMFAEnrollment)
	// must still be able to reach. NewServer derives the verifier's exempt-path
	// allowlist from routes tagged here (#243) — the route table is the single
	// source of truth, so a rename/add stays consistent by construction.
	MFAEnrollmentExempt bool
}

// APIRoutes returns AuthKit's enabled JSON API routes. With no groups it
// returns the default API surface. With groups, it returns only matching routes.
func (s *Service) APIRoutes(groups ...RouteGroup) []RouteSpec {
	if s == nil || s.svc == nil || s.verifier == nil {
		return nil
	}
	selected := routeGroupSet(groups)
	required := verify.Required(s.verifier)
	// rootPermission gates an intrinsic, root-scoped route on a `root:*`
	// permission through the granular permission system (svc.Can for users,
	// the verified ceiling for machine principals — see requirePermission).
	// There is no bespoke "admin" auth tier; these are plain root-group perms.
	rootPermission := func(perm string, h http.HandlerFunc) http.Handler {
		return required(s.requirePermission(embedded.RootPersona, "", perm, h))
	}
	optional := verify.Optional(s.verifier)
	lang := func(h http.Handler) http.Handler { return LanguageMiddleware(s.langCfg)(h) }
	routes := []RouteSpec{
		// #265: prefix-neutral like every sibling — this spec shipped as
		// "/auth/capabilities", which doubled to /auth/auth/capabilities (404)
		// on hosts anchoring the API at an /auth-style prefix.
		{Method: http.MethodGet, Path: "/capabilities", Group: RouteAuth, Auth: AuthPublic, Handler: http.HandlerFunc(s.handleCapabilitiesGET)},

		{Method: http.MethodPost, Path: "/token", Group: RouteAuth, Auth: AuthPublic, Bucket: RLAuthToken, Handler: http.HandlerFunc(s.handleAuthTokenPOST)},
		{Method: http.MethodDelete, Path: "/logout", Group: RouteAuth, Auth: AuthRequired, Bucket: RLAuthLogout, Handler: required(http.HandlerFunc(s.handleLogoutDELETE))},
		{Method: http.MethodPost, Path: "/password/login", Group: RouteAuth, Auth: AuthPublic, Bucket: RLPasswordLogin, Handler: http.HandlerFunc(s.handlePasswordLoginPOST)},
		{Method: http.MethodPost, Path: "/passwordless/start", Group: RouteAuth, Auth: AuthPublic, Bucket: RLPasswordlessStart, Handler: http.HandlerFunc(s.handlePasswordlessStartPOST)},
		{Method: http.MethodPost, Path: "/passwordless/confirm", Group: RouteAuth, Auth: AuthPublic, Bucket: RLPasswordlessConfirm, Handler: http.HandlerFunc(s.handlePasswordlessConfirmPOST)},
		{Method: http.MethodPost, Path: "/passkeys/login/begin", Group: RouteAuth, Auth: AuthPublic, Bucket: RLPasskeyLogin, Handler: http.HandlerFunc(s.handlePasskeyLoginBeginPOST)},
		{Method: http.MethodPost, Path: "/passkeys/login/finish", Group: RouteAuth, Auth: AuthPublic, Bucket: RLPasskeyLogin, Handler: http.HandlerFunc(s.handlePasskeyLoginFinishPOST)},

		{Method: http.MethodPost, Path: "/device-keys/enroll/begin", Group: RouteDeviceKeys, Auth: AuthPublic, Bucket: RLDeviceKeyEnrollBegin, Handler: http.HandlerFunc(s.handleDeviceKeyEnrollBeginPOST)},
		{Method: http.MethodPost, Path: "/device-keys/enroll/finish", Group: RouteDeviceKeys, Auth: AuthPublic, Bucket: RLDeviceKeyEnrollFinish, Handler: http.HandlerFunc(s.handleDeviceKeyEnrollFinishPOST)},
		{Method: http.MethodPost, Path: "/device-keys/login/begin", Group: RouteDeviceKeys, Auth: AuthPublic, Bucket: RLDeviceKeyLoginBegin, Handler: http.HandlerFunc(s.handleDeviceKeyLoginBeginPOST)},
		{Method: http.MethodPost, Path: "/device-keys/login/finish", Group: RouteDeviceKeys, Auth: AuthPublic, Bucket: RLDeviceKeyLoginFinish, Handler: http.HandlerFunc(s.handleDeviceKeyLoginFinishPOST)},
		{Method: http.MethodGet, Path: "/device-keys", Group: RouteDeviceKeys, Auth: AuthRequired, Bucket: RLDeviceKeysManage, Handler: required(http.HandlerFunc(s.handleDeviceKeysGET))},
		{Method: http.MethodDelete, Path: "/device-keys/{id}", Group: RouteDeviceKeys, Auth: AuthRequired, Bucket: RLDeviceKeysManage, Handler: required(http.HandlerFunc(s.handleDeviceKeyDELETE))},
		{Method: http.MethodPost, Path: "/device-keys/revoke-others", Group: RouteDeviceKeys, Auth: AuthRequired, Bucket: RLDeviceKeysManage, Handler: required(http.HandlerFunc(s.handleDeviceKeysRevokeOthersPOST))},
		{Method: http.MethodPost, Path: "/password/reset/request", Group: RouteAuth, Auth: AuthPublic, Bucket: RLPasswordResetRequest, Handler: http.HandlerFunc(s.handlePasswordResetRequestPOST)},
		{Method: http.MethodGet, Path: "/password/reset/confirm", Group: RouteAuth, Auth: AuthPublic, Handler: http.HandlerFunc(s.handlePasswordResetConfirmGET)},
		{Method: http.MethodPost, Path: "/password/reset/confirm", Group: RouteAuth, Auth: AuthPublic, Bucket: RLPasswordResetConfirm, Handler: http.HandlerFunc(s.handlePasswordResetConfirmPOST)},

		{Method: http.MethodPost, Path: "/register", Group: RouteRegistration, Auth: AuthPublic, Bucket: RLAuthRegister, Handler: http.HandlerFunc(s.handleRegisterUnifiedPOST)},
		{Method: http.MethodGet, Path: "/register/availability", Group: RouteRegistration, Auth: AuthPublic, Bucket: RLAuthRegisterAvailability, Handler: http.HandlerFunc(s.handleRegisterAvailabilityGET)},
		{Method: http.MethodPost, Path: "/register/resend", Group: RouteRegistration, Auth: AuthPublic, Bucket: RLRegisterResend, Handler: http.HandlerFunc(s.handleRegisterResendPOST)},
		{Method: http.MethodPost, Path: "/register/abandon", Group: RouteRegistration, Auth: AuthPublic, Bucket: RLAuthRegisterAbandon, Handler: http.HandlerFunc(s.handlePendingRegistrationAbandonPOST)},

		// #312: one route per contact flow; the channel comes from the identifier.
		{Method: http.MethodPost, Path: "/verify/request", Group: RouteAccount, Auth: AuthOptional, Bucket: RLVerifyRequest, Handler: optional(http.HandlerFunc(s.handleVerifyRequestPOST))},
		{Method: http.MethodGet, Path: "/verify/confirm", Group: RouteAccount, Auth: AuthPublic, Handler: http.HandlerFunc(s.handleVerifyConfirmGET)},
		{Method: http.MethodPost, Path: "/verify/confirm", Group: RouteAccount, Auth: AuthOptional, Bucket: RLVerifyConfirm, Handler: optional(http.HandlerFunc(s.handleVerifyConfirmPOST))},

		{Method: http.MethodPost, Path: "/user/password", Group: RouteAccount, Auth: AuthRequired, Bucket: RLUserPasswordChange, Handler: required(http.HandlerFunc(s.handleUserPasswordPOST))},
		{Method: http.MethodGet, Path: "/user/sessions", Group: RouteAccount, Auth: AuthRequired, Bucket: RLAuthSessionsList, Handler: required(http.HandlerFunc(s.handleUserSessionsGET))},
		{Method: http.MethodDelete, Path: "/user/sessions/{id}", Group: RouteAccount, Auth: AuthRequired, Bucket: RLAuthSessionsRevoke, Handler: required(http.HandlerFunc(s.handleUserSessionDELETE))},
		{Method: http.MethodDelete, Path: "/user/sessions", Group: RouteAccount, Auth: AuthRequired, Bucket: RLAuthSessionsRevokeAll, Handler: required(http.HandlerFunc(s.handleUserSessionsDELETE))},
		{Method: http.MethodGet, Path: "/me", Group: RouteAccount, Auth: AuthRequired, Bucket: RLUserMe, Handler: required(http.HandlerFunc(s.handleUserMeGET))},
		// #147 known-user permission-group invites: accepted/declined with the caller's own auth.
		{Method: http.MethodGet, Path: "/me/group-invites", Group: RouteAccount, Auth: AuthRequired, Handler: required(http.HandlerFunc(s.handleMeGroupInvitesGET))},
		{Method: http.MethodPost, Path: "/me/group-invites/{id}/accept", Group: RouteAccount, Auth: AuthRequired, Handler: required(http.HandlerFunc(s.handleMeGroupInviteAccept))},
		{Method: http.MethodPost, Path: "/me/group-invites/{id}/decline", Group: RouteAccount, Auth: AuthRequired, Handler: required(http.HandlerFunc(s.handleMeGroupInviteDecline))},
		// #193 self-service leave: a user removes themself from a group with their own auth.
		// #262 user-metadata surface (host-namespaced keys; authkit-internal
		// flags are filtered from reads and rejected on writes).
		{Method: http.MethodPatch, Path: "/user/username", Group: RouteAccount, Auth: AuthRequired, Bucket: RLUserUpdateUsername, Handler: required(http.HandlerFunc(s.handleUserUsernamePATCH))},
		{Method: http.MethodPatch, Path: "/user/preferred-language", Group: RouteAccount, Auth: AuthRequired, Bucket: RLUserPreferredLanguage, Handler: required(http.HandlerFunc(s.handleUserPreferredLanguagePATCH))},
		{Method: http.MethodDelete, Path: "/user", Group: RouteAccount, Auth: AuthRequired, Bucket: RLUserDelete, Handler: required(http.HandlerFunc(s.handleUserDeleteDELETE))},
		{Method: http.MethodDelete, Path: "/user/providers/{provider}", Group: RouteAccount, Auth: AuthRequired, Bucket: RLUserUnlinkProvider, Handler: required(http.HandlerFunc(s.handleUserUnlinkProviderDELETE))},
		{Method: http.MethodPost, Path: "/passkeys/register/begin", Group: RouteAccount, Auth: AuthRequired, Bucket: RLPasskeyRegister, Handler: required(http.HandlerFunc(s.handlePasskeyRegisterBeginPOST))},
		{Method: http.MethodPost, Path: "/passkeys/register/finish", Group: RouteAccount, Auth: AuthRequired, Bucket: RLPasskeyRegister, Handler: required(http.HandlerFunc(s.handlePasskeyRegisterFinishPOST))},
		{Method: http.MethodGet, Path: "/passkeys", Group: RouteAccount, Auth: AuthRequired, Handler: required(http.HandlerFunc(s.handlePasskeysGET))},
		{Method: http.MethodPatch, Path: "/passkeys/{id}", Group: RouteAccount, Auth: AuthRequired, Handler: required(http.HandlerFunc(s.handlePasskeyPATCH))},
		{Method: http.MethodDelete, Path: "/passkeys/{id}", Group: RouteAccount, Auth: AuthRequired, Handler: required(http.HandlerFunc(s.handlePasskeyDELETE))},

		{Method: http.MethodPost, Path: "/step-up/password", Group: RouteAccount, Auth: AuthRequired, Handler: required(http.HandlerFunc(s.handlePasswordStepUpPOST))},
		{Method: http.MethodPost, Path: "/step-up/2fa", Group: RouteAccount, Auth: AuthRequired, Handler: required(http.HandlerFunc(s.handleTwoFactorStepUpPOST))},

		{Method: http.MethodPost, Path: "/oidc/{provider}/link/start", Group: RouteAccount, Auth: AuthRequired, Handler: required(http.HandlerFunc(s.handleOIDCLinkStartPOST))},
		{Method: http.MethodPost, Path: "/oidc/{provider}/step-up/start", Group: RouteAccount, Auth: AuthRequired, Handler: required(http.HandlerFunc(s.handleOIDCStepUpStartPOST))},

		{Method: http.MethodGet, Path: "/user/2fa", Group: RouteAccount, Auth: AuthRequired, Bucket: RLUserMe, Handler: required(http.HandlerFunc(s.handleUser2FAStatusGET)), MFAEnrollmentExempt: true},
		{Method: http.MethodPost, Path: "/user/2fa", Group: RouteAccount, Auth: AuthRequired, Bucket: RL2FAEnable, Handler: required(http.HandlerFunc(s.handleUser2FAPOST)), MFAEnrollmentExempt: true},
		{Method: http.MethodDelete, Path: "/user/2fa", Group: RouteAccount, Auth: AuthRequired, Bucket: RL2FADisable, Handler: required(http.HandlerFunc(s.handleUser2FADELETE)), MFAEnrollmentExempt: true},
		{Method: http.MethodPost, Path: "/user/2fa/backup-codes", Group: RouteAccount, Auth: AuthRequired, Bucket: RL2FARegenerateCodes, Handler: required(http.HandlerFunc(s.handleUser2FABackupCodesPOST)), MFAEnrollmentExempt: true},
		{Method: http.MethodPost, Path: "/2fa/challenge", Group: RouteAuth, Auth: AuthPublic, Bucket: RL2FAVerify, Handler: http.HandlerFunc(s.handleUser2FAChallengePOST), MFAEnrollmentExempt: true},
		{Method: http.MethodPost, Path: "/2fa/verify", Group: RouteAuth, Auth: AuthPublic, Bucket: RL2FAVerify, Handler: http.HandlerFunc(s.handleUser2FAVerifyPOST), MFAEnrollmentExempt: true},

		{Method: http.MethodPost, Path: "/solana/challenge", Group: RouteAuth, Auth: AuthPublic, Bucket: RLSolanaChallenge, Handler: http.HandlerFunc(s.handleSolanaChallengePOST)},
		{Method: http.MethodPost, Path: "/solana/login", Group: RouteAuth, Auth: AuthPublic, Bucket: RLSolanaLogin, Handler: http.HandlerFunc(s.handleSolanaLoginPOST)},
		{Method: http.MethodPost, Path: "/solana/link", Group: RouteAccount, Auth: AuthRequired, Bucket: RLSolanaLink, Handler: required(http.HandlerFunc(s.handleSolanaLinkPOST))},

		// Intrinsic user-admin directory. Auth is permission-based: human users
		// authorize through the root permission-group, programmatic principals via
		// their verified permission ceiling.
		{Method: http.MethodGet, Path: "/admin/users", Group: RouteAdmin, Auth: AuthPermission, Permission: embedded.PermRootResourcesRead, Bucket: RLAdminUserSessionsList, Handler: rootPermission(embedded.PermRootResourcesRead, s.handleAdminUsersListGET)},
		{Method: http.MethodGet, Path: "/admin/users/{user_id}", Group: RouteAdmin, Auth: AuthPermission, Permission: embedded.PermRootResourcesRead, Handler: rootPermission(embedded.PermRootResourcesRead, s.handleAdminUserGET)},
		{Method: http.MethodGet, Path: "/admin/users/{user_id}/signins", Group: RouteAdmin, Auth: AuthPermission, Permission: embedded.PermRootResourcesRead, Handler: rootPermission(embedded.PermRootResourcesRead, s.handleAdminUserSigninsGET)},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/ban", Group: RouteAdmin, Auth: AuthPermission, Permission: embedded.PermRootUsersBan, Bucket: RLAdminUserSessionsRevokeAll, Handler: rootPermission(embedded.PermRootUsersBan, s.handleAdminUsersBanPOST)},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/unban", Group: RouteAdmin, Auth: AuthPermission, Permission: embedded.PermRootUsersBan, Bucket: RLAdminUserSessionsRevokeAll, Handler: rootPermission(embedded.PermRootUsersBan, s.handleAdminUsersUnbanPOST)},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/sessions/revoke", Group: RouteAdmin, Auth: AuthPermission, Permission: embedded.PermRootUsersRecover, Bucket: RLAdminUserSessionsRevokeAll, Handler: rootPermission(embedded.PermRootUsersRecover, s.handleAdminUserSessionsRevokePOST)},
		{Method: http.MethodDelete, Path: "/admin/users/{user_id}", Group: RouteAdmin, Auth: AuthPermission, Permission: embedded.PermRootUsersDelete, Bucket: RLAdminUserSessionsRevokeAll, Handler: rootPermission(embedded.PermRootUsersDelete, s.handleAdminUserDeleteDELETE)},

		// #264 application self-registration: unauthenticated by design — the
		// domain proof / per-message JWS is the authentication. Mounted only
		// when Applications.SelfRegistration is enabled (see filter below).
		{Method: http.MethodPost, Path: "/applications/register", Group: RouteApplications, Auth: AuthSigned, Bucket: RLApplicationRegister, Handler: http.HandlerFunc(s.handleApplicationRegisterPOST)},
		// Tier changes are an admin act; mounted regardless of self-registration
		// (manual registrations carry tiers too).

		// #261 delegated-token mint: authenticated users exchange their session
		// for a short-lived delegated token aimed at the configured audiences.
		// Mounted only when Config.Delegated is enabled (see filter below).
		{Method: http.MethodPost, Path: "/delegated/token", Group: RouteDelegated, Auth: AuthRequired, Bucket: RLDelegatedTokenMint, Handler: required(http.HandlerFunc(s.handleDelegatedTokenPOST))},
	}

	// Passkey routes are mounted only when passkeys are configured. Without a
	// Relying Party ID the WebAuthn ceremonies fail closed, so exposing the
	// /passkeys/* endpoints would just serve guaranteed errors. Embedders that
	// set PasskeyConfig.RPID get the routes; everyone else doesn't advertise a
	// feature they can't fulfil.
	passkeysEnabled := s.svc.PasskeysEnabled()
	cfg := s.svc.Config()
	passwordlessEnabled := cfg.Registration.PasswordlessLogin
	registrationEnabled := cfg.Registration.NativeUserMode != embedded.RegistrationModeClosed
	twoFactorEnabled := s.svc.TwoFactorEnabled()
	solanaEnabled := strings.TrimSpace(cfg.SolanaNetwork) != ""
	oidcEnabled := len(s.providers) > 0
	applicationsEnabled := cfg.Applications.SelfRegistration
	delegatedEnabled := len(cfg.Delegated.Audiences) > 0
	deviceKeysEnabled := cfg.DeviceKeys.Enabled
	out := make([]RouteSpec, 0, len(routes))
	for _, route := range routes {
		if !selected(route.Group) {
			continue
		}
		if route.Group == RouteDelegated && !delegatedEnabled {
			continue
		}
		if route.Group == RouteDeviceKeys && !deviceKeysEnabled {
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
		if isApplicationsPath(route.Path) && !applicationsEnabled {
			continue
		}
		route.Handler = lang(s.rateLimitedRoute(route.Bucket, route.Handler))
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
	return path == "/register" || path == "/register/abandon" || path == "/register/resend"
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

func isApplicationsPath(path string) bool {
	return strings.HasPrefix(path, "/applications/")
}

// OIDCBrowserRoutes returns browser redirect routes with no mount prefix.
func (s *Service) OIDCBrowserRoutes(groups ...RouteGroup) []RouteSpec {
	if s == nil || s.svc == nil {
		return nil
	}
	if len(s.providers) == 0 {
		return nil
	}
	selected := routeGroupSet(groups)
	lang := func(h http.Handler) http.Handler { return LanguageMiddleware(s.langCfg)(h) }
	routes := []RouteSpec{
		{Method: http.MethodGet, Path: "/{provider}/login", Group: RouteBrowserOIDC, Auth: AuthPublic, Handler: http.HandlerFunc(s.handleOIDCLoginGET)},
		{Method: http.MethodGet, Path: "/{provider}/callback", Group: RouteBrowserOIDC, Auth: AuthPublic, Bucket: RLOIDCCallback, Handler: http.HandlerFunc(s.handleOIDCCallbackGET)},
		{Method: http.MethodGet, Path: "/{provider}/step-up/callback", Group: RouteBrowserOIDC, Auth: AuthPublic, Bucket: RLOIDCCallback, Handler: http.HandlerFunc(s.handleOIDCCallbackGET)},
		// response_mode=form_post providers (Apple) deliver the same response as a
		// cross-site POST body (#295).
		{Method: http.MethodPost, Path: "/{provider}/callback", Group: RouteBrowserOIDC, Auth: AuthPublic, Bucket: RLOIDCCallback, Handler: http.HandlerFunc(s.handleOIDCCallbackGET)},
		{Method: http.MethodPost, Path: "/{provider}/step-up/callback", Group: RouteBrowserOIDC, Auth: AuthPublic, Bucket: RLOIDCCallback, Handler: http.HandlerFunc(s.handleOIDCCallbackGET)},
	}
	out := make([]RouteSpec, 0, len(routes))
	for _, route := range routes {
		if !selected(route.Group) {
			continue
		}
		route.Handler = lang(s.rateLimitedRoute(route.Bucket, route.Handler))
		out = append(out, route)
	}
	return out
}

// rateLimitedRoute applies the route's per-IP bucket in front of next (#328):
// the registry, not each handler, owns the entry check.
func (s *Service) rateLimitedRoute(bucket string, next http.Handler) http.Handler {
	if bucket == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.rateLimited(w, r, bucket) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Requires names the configuration that mounts the route ("" = always
// mounted). It mirrors the APIRoutes/OIDCBrowserRoutes filters, so the
// generated route documentation and the mount decision cannot drift.
func (r RouteSpec) Requires() string {
	switch {
	case r.Group == RouteDelegated:
		return "Delegated.Audiences"
	case r.Group == RouteDeviceKeys:
		return "DeviceKeys.Enabled"
	case r.Group == RouteDocuments:
		return "WithDocuments"
	case r.Group == RouteBrowserOIDC, isOIDCPath(r.Path):
		return "Identity.Providers"
	case r.Group == RoutePermissionGroups, r.Path == "/me/groups":
		return "RBAC persona profile"
	case isPasskeyPath(r.Path):
		return "Passkeys.RPID"
	case isPasswordlessPath(r.Path):
		return "Registration.PasswordlessLogin"
	case isRegistrationMutationPath(r.Path):
		return "Registration.NativeUserMode != closed"
	case isTwoFactorPath(r.Path):
		return "TwoFactor.Mode != disabled"
	case isSolanaPath(r.Path):
		return "SolanaNetwork"
	case isApplicationsPath(r.Path):
		return "Applications.SelfRegistration"
	}
	return ""
}

// mfaEnrollmentExemptPaths returns the distinct Path values of the routes tagged
// MFAEnrollmentExempt — the authoritative 2FA enroll/challenge/verify surface a
// forced-enrollment-gated request must still reach (#243). NewServer feeds this
// into the verifier via verify.Verifier.SetMFAEnrollmentExemptPaths so the gate's
// allowlist is derived from the route registry rather than a hand-maintained list.
func mfaEnrollmentExemptPaths(specs []RouteSpec) []string {
	seen := make(map[string]bool, len(specs))
	out := make([]string, 0, len(specs))
	for _, spec := range specs {
		if !spec.MFAEnrollmentExempt || seen[spec.Path] {
			continue
		}
		seen[spec.Path] = true
		out = append(out, spec.Path)
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
