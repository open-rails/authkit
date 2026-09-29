package httpapi

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

// RouteSpec is a concrete, prefix-neutral route with its AuthKit handler
// attached. Path parameters use net/http ServeMux syntax, e.g.
// "/namespaces/{slug}".
type RouteSpec struct {
	Method  string
	Path    string
	Group   iam.RouteGroup
	Handler http.Handler
	// Auth is the tier the handler wrapper enforces before the handler runs;
	// Permission names the root/group permission for AuthPermission (#328).
	Auth       iam.RouteAuthTier
	Permission string
	// Bucket is the per-IP rate-limit bucket APIRoutes applies in front of the
	// handler ("" = none). Per-identifier and branch-specific buckets stay in
	// the handler.
	Bucket string
	// MFAEnrollmentExempt marks a route as part of the 2FA enroll/challenge/
	// verify surface a forced-enrollment-gated user (verify.WithRequireMFAEnrollment)
	// must still be able to reach. httpapi.New derives the verifier's exempt-path
	// allowlist from routes tagged here (#243) — the route table is the single
	// source of truth, so a rename/add stays consistent by construction.
	MFAEnrollmentExempt bool
}

// APIRoutes returns AuthKit's enabled JSON API routes. With no groups it
// returns the default API surface. With groups, it returns only matching routes.
func (s *Service) APIRoutes(groups ...iam.RouteGroup) []RouteSpec {
	if s == nil || s.svc == nil || s.verifier == nil {
		return nil
	}
	selected := routeGroupSet(groups)
	required := verify.Required(s.verifier)
	// rootPermission gates an intrinsic, root-scoped route on a `root:*`
	// permission through the granular permission system (the engine's live
	// Can for every actor kind — see requirePermission).
	// Native account status follows token issuance unless the host explicitly
	// adds live-account middleware; the permission lookup itself is always live.
	// There is no bespoke "admin" auth tier; these are plain root-group perms.
	rootPermission := func(perm iam.Perm, h http.HandlerFunc) http.Handler {
		return required(s.requirePermission(iam.RootGroup(), perm, h))
	}
	optional := verify.Optional(s.verifier)
	lang := func(h http.Handler) http.Handler { return LanguageMiddleware(s.langCfg)(h) }
	routes := []RouteSpec{
		// #265: prefix-neutral like every sibling — this spec shipped as
		// "/auth/capabilities", which doubled to /auth/auth/capabilities (404)
		// on hosts anchoring the API at an /auth-style prefix.
		{Method: http.MethodGet, Path: "/capabilities", Group: iam.RouteAuth, Auth: iam.AuthPublic, Handler: http.HandlerFunc(s.handleCapabilitiesGET)},

		{Method: http.MethodPost, Path: "/token", Group: iam.RouteAuth, Auth: iam.AuthPublic, Bucket: RLAuthToken, Handler: http.HandlerFunc(s.handleAuthTokenPOST)},
		{Method: http.MethodDelete, Path: "/logout", Group: iam.RouteAuth, Auth: iam.AuthRequired, Bucket: RLAuthLogout, Handler: required(http.HandlerFunc(s.handleLogoutDELETE))},
		{Method: http.MethodPost, Path: "/password/login", Group: iam.RouteAuth, Auth: iam.AuthPublic, Bucket: RLPasswordLogin, Handler: http.HandlerFunc(s.handlePasswordLoginPOST)},
		{Method: http.MethodPost, Path: "/account/recovery/confirm", Group: iam.RouteAuth, Auth: iam.AuthPublic, Bucket: RLPasswordLogin, Handler: http.HandlerFunc(s.handleAccountRecoveryConfirmPOST)},
		{Method: http.MethodPost, Path: "/passwordless/start", Group: iam.RouteAuth, Auth: iam.AuthPublic, Bucket: RLPasswordlessStart, Handler: http.HandlerFunc(s.handlePasswordlessStartPOST)},
		{Method: http.MethodPost, Path: "/passwordless/confirm", Group: iam.RouteAuth, Auth: iam.AuthPublic, Bucket: RLPasswordlessConfirm, Handler: http.HandlerFunc(s.handlePasswordlessConfirmPOST)},
		{Method: http.MethodPost, Path: "/passkeys/login/begin", Group: iam.RouteAuth, Auth: iam.AuthPublic, Bucket: RLPasskeyLogin, Handler: http.HandlerFunc(s.handlePasskeyLoginBeginPOST)},
		{Method: http.MethodPost, Path: "/passkeys/login/finish", Group: iam.RouteAuth, Auth: iam.AuthPublic, Bucket: RLPasskeyLogin, Handler: http.HandlerFunc(s.handlePasskeyLoginFinishPOST)},

		{Method: http.MethodPost, Path: "/device-keys/enroll/begin", Group: iam.RouteDeviceKeys, Auth: iam.AuthPublic, Bucket: RLDeviceKeyEnrollBegin, Handler: http.HandlerFunc(s.handleDeviceKeyEnrollBeginPOST)},
		{Method: http.MethodPost, Path: "/device-keys/enroll/finish", Group: iam.RouteDeviceKeys, Auth: iam.AuthPublic, Bucket: RLDeviceKeyEnrollFinish, Handler: http.HandlerFunc(s.handleDeviceKeyEnrollFinishPOST)},
		{Method: http.MethodPost, Path: "/device-keys/login/begin", Group: iam.RouteDeviceKeys, Auth: iam.AuthPublic, Bucket: RLDeviceKeyLoginBegin, Handler: http.HandlerFunc(s.handleDeviceKeyLoginBeginPOST)},
		{Method: http.MethodPost, Path: "/device-keys/login/finish", Group: iam.RouteDeviceKeys, Auth: iam.AuthPublic, Bucket: RLDeviceKeyLoginFinish, Handler: http.HandlerFunc(s.handleDeviceKeyLoginFinishPOST)},
		{Method: http.MethodGet, Path: "/device-keys", Group: iam.RouteDeviceKeys, Auth: iam.AuthRequired, Bucket: RLDeviceKeysManage, Handler: required(http.HandlerFunc(s.handleDeviceKeysGET))},
		{Method: http.MethodDelete, Path: "/device-keys/{id}", Group: iam.RouteDeviceKeys, Auth: iam.AuthRequired, Bucket: RLDeviceKeysManage, Handler: required(http.HandlerFunc(s.handleDeviceKeyDELETE))},
		{Method: http.MethodPost, Path: "/device-keys/revoke-others", Group: iam.RouteDeviceKeys, Auth: iam.AuthRequired, Bucket: RLDeviceKeysManage, Handler: required(http.HandlerFunc(s.handleDeviceKeysRevokeOthersPOST))},
		{Method: http.MethodPost, Path: "/password/reset/request", Group: iam.RouteAuth, Auth: iam.AuthPublic, Bucket: RLPasswordResetRequest, Handler: http.HandlerFunc(s.handlePasswordResetRequestPOST)},
		{Method: http.MethodPost, Path: "/password/reset/confirm", Group: iam.RouteAuth, Auth: iam.AuthPublic, Bucket: RLPasswordResetConfirm, Handler: http.HandlerFunc(s.handlePasswordResetConfirmPOST)},

		{Method: http.MethodPost, Path: "/register", Group: iam.RouteRegistration, Auth: iam.AuthPublic, Bucket: RLAuthRegister, Handler: http.HandlerFunc(s.handleRegisterUnifiedPOST)},
		{Method: http.MethodGet, Path: "/register/availability", Group: iam.RouteRegistration, Auth: iam.AuthPublic, Bucket: RLAuthRegisterAvailability, Handler: http.HandlerFunc(s.handleRegisterAvailabilityGET)},
		{Method: http.MethodPost, Path: "/register/abandon", Group: iam.RouteRegistration, Auth: iam.AuthPublic, Bucket: RLAuthRegisterAbandon, Handler: http.HandlerFunc(s.handlePendingRegistrationAbandonPOST)},

		// #312: one route per contact flow; the channel comes from the identifier.
		{Method: http.MethodPost, Path: "/verify/request", Group: iam.RouteAccount, Auth: iam.AuthOptional, Bucket: RLVerifyRequest, Handler: optional(http.HandlerFunc(s.handleVerifyRequestPOST))},
		{Method: http.MethodPost, Path: "/verify/confirm", Group: iam.RouteAccount, Auth: iam.AuthOptional, Bucket: RLVerifyConfirm, Handler: optional(http.HandlerFunc(s.handleVerifyConfirmPOST))},

		{Method: http.MethodPost, Path: "/user/password", Group: iam.RouteAccount, Auth: iam.AuthRequired, Bucket: RLUserPasswordChange, Handler: required(http.HandlerFunc(s.handleUserPasswordPOST))},
		{Method: http.MethodGet, Path: "/user/sessions", Group: iam.RouteAccount, Auth: iam.AuthRequired, Bucket: RLAuthSessionsList, Handler: required(http.HandlerFunc(s.handleUserSessionsGET))},
		{Method: http.MethodDelete, Path: "/user/sessions/{id}", Group: iam.RouteAccount, Auth: iam.AuthRequired, Bucket: RLAuthSessionsRevoke, Handler: required(http.HandlerFunc(s.handleUserSessionDELETE))},
		{Method: http.MethodDelete, Path: "/user/sessions", Group: iam.RouteAccount, Auth: iam.AuthRequired, Bucket: RLAuthSessionsRevokeAll, Handler: required(http.HandlerFunc(s.handleUserSessionsDELETE))},
		{Method: http.MethodGet, Path: "/me", Group: iam.RouteAccount, Auth: iam.AuthRequired, Bucket: RLUserMe, Handler: required(http.HandlerFunc(s.handleUserMeGET))},
		// #193 self-service leave: a user removes themself from a group with their own auth.
		// #262 user-metadata surface (host-namespaced keys; authkit-internal
		// flags are filtered from reads and rejected on writes).
		{Method: http.MethodPatch, Path: "/user/username", Group: iam.RouteAccount, Auth: iam.AuthRequired, Bucket: RLUserUpdateUsername, Handler: required(http.HandlerFunc(s.handleUserUsernamePATCH))},
		{Method: http.MethodPatch, Path: "/user/preferred-language", Group: iam.RouteAccount, Auth: iam.AuthRequired, Bucket: RLUserPreferredLanguage, Handler: required(http.HandlerFunc(s.handleUserPreferredLanguagePATCH))},
		{Method: http.MethodDelete, Path: "/user", Group: iam.RouteAccount, Auth: iam.AuthRequired, Bucket: RLUserDelete, Handler: required(http.HandlerFunc(s.handleUserDeleteDELETE))},
		{Method: http.MethodDelete, Path: "/user/providers/{provider}", Group: iam.RouteAccount, Auth: iam.AuthRequired, Bucket: RLUserUnlinkProvider, Handler: required(http.HandlerFunc(s.handleUserUnlinkProviderDELETE))},
		{Method: http.MethodPost, Path: "/passkeys/register/begin", Group: iam.RouteAccount, Auth: iam.AuthRequired, Bucket: RLPasskeyRegister, Handler: required(http.HandlerFunc(s.handlePasskeyRegisterBeginPOST))},
		{Method: http.MethodPost, Path: "/passkeys/register/finish", Group: iam.RouteAccount, Auth: iam.AuthRequired, Bucket: RLPasskeyRegister, Handler: required(http.HandlerFunc(s.handlePasskeyRegisterFinishPOST))},
		{Method: http.MethodGet, Path: "/passkeys", Group: iam.RouteAccount, Auth: iam.AuthRequired, Handler: required(http.HandlerFunc(s.handlePasskeysGET))},
		{Method: http.MethodPatch, Path: "/passkeys/{id}", Group: iam.RouteAccount, Auth: iam.AuthRequired, Handler: required(http.HandlerFunc(s.handlePasskeyPATCH))},
		{Method: http.MethodDelete, Path: "/passkeys/{id}", Group: iam.RouteAccount, Auth: iam.AuthRequired, Handler: required(http.HandlerFunc(s.handlePasskeyDELETE))},

		{Method: http.MethodPost, Path: "/step-up/password", Group: iam.RouteAccount, Auth: iam.AuthRequired, Bucket: RLPasswordStepUp, Handler: required(http.HandlerFunc(s.handlePasswordStepUpPOST))},
		{Method: http.MethodPost, Path: "/step-up/2fa", Group: iam.RouteAccount, Auth: iam.AuthRequired, Handler: required(http.HandlerFunc(s.handleTwoFactorStepUpPOST))},

		{Method: http.MethodPost, Path: "/oidc/{provider}/link/start", Group: iam.RouteAccount, Auth: iam.AuthRequired, Handler: required(http.HandlerFunc(s.handleOIDCLinkStartPOST))},
		{Method: http.MethodPost, Path: "/oidc/{provider}/step-up/start", Group: iam.RouteAccount, Auth: iam.AuthRequired, Handler: required(http.HandlerFunc(s.handleOIDCStepUpStartPOST))},

		{Method: http.MethodGet, Path: "/user/2fa", Group: iam.RouteAccount, Auth: iam.AuthRequired, Bucket: RLUserMe, Handler: required(http.HandlerFunc(s.handleUser2FAStatusGET)), MFAEnrollmentExempt: true},
		{Method: http.MethodPost, Path: "/user/2fa", Group: iam.RouteAccount, Auth: iam.AuthRequired, Bucket: RL2FAEnable, Handler: required(http.HandlerFunc(s.handleUser2FAPOST)), MFAEnrollmentExempt: true},
		{Method: http.MethodDelete, Path: "/user/2fa", Group: iam.RouteAccount, Auth: iam.AuthRequired, Bucket: RL2FADisable, Handler: required(http.HandlerFunc(s.handleUser2FADELETE)), MFAEnrollmentExempt: true},
		{Method: http.MethodPost, Path: "/user/2fa/backup-codes", Group: iam.RouteAccount, Auth: iam.AuthRequired, Bucket: RL2FARegenerateCodes, Handler: required(http.HandlerFunc(s.handleUser2FABackupCodesPOST)), MFAEnrollmentExempt: true},
		{Method: http.MethodPost, Path: "/2fa/challenge", Group: iam.RouteAuth, Auth: iam.AuthPublic, Bucket: RL2FAVerify, Handler: http.HandlerFunc(s.handleUser2FAChallengePOST), MFAEnrollmentExempt: true},
		{Method: http.MethodPost, Path: "/2fa/verify", Group: iam.RouteAuth, Auth: iam.AuthPublic, Bucket: RL2FAVerify, Handler: http.HandlerFunc(s.handleUser2FAVerifyPOST), MFAEnrollmentExempt: true},

		{Method: http.MethodPost, Path: "/solana/challenge", Group: iam.RouteAuth, Auth: iam.AuthPublic, Bucket: RLSolanaChallenge, Handler: http.HandlerFunc(s.handleSolanaChallengePOST)},
		{Method: http.MethodPost, Path: "/solana/login", Group: iam.RouteAuth, Auth: iam.AuthPublic, Bucket: RLSolanaLogin, Handler: http.HandlerFunc(s.handleSolanaLoginPOST)},
		{Method: http.MethodPost, Path: "/solana/link", Group: iam.RouteAccount, Auth: iam.AuthRequired, Bucket: RLSolanaLink, Handler: required(http.HandlerFunc(s.handleSolanaLinkPOST))},

		// Intrinsic user-admin directory. Auth is permission-based: human users
		// authorize through the root permission-group, programmatic principals via
		// their verified permission ceiling.
		{Method: http.MethodGet, Path: "/admin/users", Group: iam.RouteAdmin, Auth: iam.AuthPermission, Permission: iam.PermRootUsersRead.String(), Bucket: RLAdminUserSessionsList, Handler: rootPermission(iam.PermRootUsersRead, s.handleAdminUsersListGET)},
		{Method: http.MethodGet, Path: "/admin/users/{user_id}", Group: iam.RouteAdmin, Auth: iam.AuthPermission, Permission: iam.PermRootUsersRead.String(), Handler: rootPermission(iam.PermRootUsersRead, s.handleAdminUserGET)},
		{Method: http.MethodGet, Path: "/admin/users/{user_id}/signins", Group: iam.RouteAdmin, Auth: iam.AuthPermission, Permission: iam.PermRootUsersRead.String(), Handler: rootPermission(iam.PermRootUsersRead, s.handleAdminUserSigninsGET)},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/ban", Group: iam.RouteAdmin, Auth: iam.AuthRequired, Bucket: RLAdminUserSessionsRevokeAll, Handler: required(http.HandlerFunc(s.handleAdminUsersBanPOST))},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/unban", Group: iam.RouteAdmin, Auth: iam.AuthRequired, Bucket: RLAdminUserSessionsRevokeAll, Handler: required(http.HandlerFunc(s.handleAdminUsersUnbanPOST))},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/sessions/revoke", Group: iam.RouteAdmin, Auth: iam.AuthRequired, Bucket: RLAdminUserSessionsRevokeAll, Handler: required(http.HandlerFunc(s.handleAdminUserSessionsRevokePOST))},
		{Method: http.MethodDelete, Path: "/admin/users/{user_id}", Group: iam.RouteAdmin, Auth: iam.AuthRequired, Bucket: RLAdminUserSessionsRevokeAll, Handler: required(http.HandlerFunc(s.handleAdminUserDeleteDELETE))},
		{Method: http.MethodPost, Path: "/admin/users/{user_id}/restore", Group: iam.RouteAdmin, Auth: iam.AuthRequired, Bucket: RLAdminUserSessionsRevokeAll, Handler: required(http.HandlerFunc(s.handleAdminUserRestorePOST))},
		// Root-role administration: the engine enforces root:members:manage,
		// role coverage, the last owner and MFA.
		{Method: http.MethodGet, Path: "/admin/roles", Group: iam.RouteAdmin, Auth: iam.AuthPermission, Permission: iam.PermMembersRead(iam.RootPersona).String(), Handler: rootPermission(iam.PermMembersRead(iam.RootPersona), s.handleAdminRolesGET)},
		{Method: http.MethodPut, Path: "/admin/users/{user_id}/roles/{role}", Group: iam.RouteAdmin, Auth: iam.AuthRequired, Bucket: RLAdminUserSessionsRevokeAll, Handler: required(http.HandlerFunc(s.handleAdminUserRolePUT))},
		{Method: http.MethodDelete, Path: "/admin/users/{user_id}/roles/{role}", Group: iam.RouteAdmin, Auth: iam.AuthRequired, Bucket: RLAdminUserSessionsRevokeAll, Handler: required(http.HandlerFunc(s.handleAdminUserRoleDELETE))},

		// #261 delegated-token mint: authenticated users exchange their session
		// for a short-lived delegated token aimed at the configured audiences.
		// Mounted only when Config.Delegated is enabled (see filter below).
		{Method: http.MethodPost, Path: "/delegated/token", Group: iam.RouteDelegated, Auth: iam.AuthRequired, Bucket: RLDelegatedTokenMint, Handler: required(http.HandlerFunc(s.handleDelegatedTokenPOST))},
	}

	// Passkey routes are mounted only when passkeys are configured. Without a
	// Relying Party ID the WebAuthn ceremonies fail closed, so exposing the
	// /passkeys/* endpoints would just serve guaranteed errors. Embedders that
	// set PasskeyConfig.RPID get the routes; everyone else doesn't advertise a
	// feature they can't fulfil.
	passkeysEnabled := s.svc.PasskeysEnabled()
	cfg := s.settings
	passwordlessEnabled := cfg.PasswordlessLogin
	registrationEnabled := cfg.RegistrationMode != iam.RegistrationModeClosed
	twoFactorEnabled := s.svc.TwoFactorEnabled()
	solanaEnabled := cfg.SolanaNetwork != ""
	oidcEnabled := len(s.providers) > 0
	delegatedEnabled := len(cfg.Delegated.Audiences) > 0
	deviceKeysEnabled := cfg.DeviceKeys
	out := make([]RouteSpec, 0, len(routes))
	for _, route := range routes {
		if !selected(route.Group) {
			continue
		}
		if route.Group == iam.RouteDelegated && !delegatedEnabled {
			continue
		}
		if route.Group == iam.RouteDeviceKeys && !deviceKeysEnabled {
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
	return path == "/register" || path == "/register/abandon"
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
func (s *Service) OIDCBrowserRoutes(groups ...iam.RouteGroup) []RouteSpec {
	if s == nil || s.svc == nil {
		return nil
	}
	if len(s.providers) == 0 {
		return nil
	}
	selected := routeGroupSet(groups)
	lang := func(h http.Handler) http.Handler { return LanguageMiddleware(s.langCfg)(h) }
	routes := []RouteSpec{
		{Method: http.MethodGet, Path: "/{provider}/login", Group: iam.RouteBrowserOIDC, Auth: iam.AuthPublic, Handler: http.HandlerFunc(s.handleOIDCLoginGET)},
		{Method: http.MethodPost, Path: "/{provider}/login", Group: iam.RouteBrowserOIDC, Auth: iam.AuthPublic, Handler: http.HandlerFunc(s.handleOIDCLoginPOST)},
		{Method: http.MethodGet, Path: "/{provider}/callback", Group: iam.RouteBrowserOIDC, Auth: iam.AuthPublic, Bucket: RLOIDCCallback, Handler: http.HandlerFunc(s.handleOIDCCallbackGET)},
		{Method: http.MethodGet, Path: "/{provider}/step-up/callback", Group: iam.RouteBrowserOIDC, Auth: iam.AuthPublic, Bucket: RLOIDCCallback, Handler: http.HandlerFunc(s.handleOIDCCallbackGET)},
		// response_mode=form_post providers (Apple) deliver the same response as a
		// cross-site POST body (#295).
		{Method: http.MethodPost, Path: "/{provider}/callback", Group: iam.RouteBrowserOIDC, Auth: iam.AuthPublic, Bucket: RLOIDCCallback, Handler: http.HandlerFunc(s.handleOIDCCallbackGET)},
		{Method: http.MethodPost, Path: "/{provider}/step-up/callback", Group: iam.RouteBrowserOIDC, Auth: iam.AuthPublic, Bucket: RLOIDCCallback, Handler: http.HandlerFunc(s.handleOIDCCallbackGET)},
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

// mfaEnrollmentExemptPaths returns the distinct Path values of the routes tagged
// MFAEnrollmentExempt — the authoritative 2FA enroll/challenge/verify surface a
// forced-enrollment-gated request must still reach (#243). NewMount anchors these
// at its prefix and registers them with verify.Verifier.AddMFAEnrollmentExemptRoutes, so the gate's
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

func routeGroupSet(groups []iam.RouteGroup) func(iam.RouteGroup) bool {
	if len(groups) == 0 {
		return func(iam.RouteGroup) bool { return true }
	}
	set := make(map[iam.RouteGroup]struct{}, len(groups))
	for _, group := range groups {
		set[group] = struct{}{}
	}
	return func(group iam.RouteGroup) bool {
		_, ok := set[group]
		return ok
	}
}
