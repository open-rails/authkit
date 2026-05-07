package authhttp

import (
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

// JWKSHandler returns a handler for GET /.well-known/jwks.json.
func (s *Service) JWKSHandler() http.Handler {
	return JWKSHandler(s.svc.JWKS())
}

// APIHandler returns a handler that serves prefix-neutral JSON API routes.
// It is intended to be mounted under the host's mux/router at the host's chosen API prefix.
func (s *Service) APIHandler() http.Handler {
	if s == nil || s.svc == nil || s.verifier == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serverErr(w, "authkit_not_initialized") })
	}
	if err := s.svc.ValidateVerificationConfiguration(); err != nil {
		panic(err)
	}
	if !core.IsDevEnvironment(s.svc.Options().Environment) {
		if s.svc.EphemeralMode() != core.EphemeralRedis {
			panic("authkit: redis-compatible ephemeral store is required in production")
		}
	}

	mux := http.NewServeMux()

	// Sessions + logout
	mux.Handle("POST /token", http.HandlerFunc(s.handleAuthTokenPOST))
	mux.Handle("POST /sessions/current", http.HandlerFunc(s.handleAuthSessionsCurrentPOST))

	// Registration + login
	mux.Handle("POST /password/login", http.HandlerFunc(s.handlePasswordLoginPOST))
	mux.Handle("POST /register", http.HandlerFunc(s.handleRegisterUnifiedPOST))
	mux.Handle("POST /register/resend-email", http.HandlerFunc(s.handlePendingRegistrationResendPOST))
	mux.Handle("POST /register/resend-phone", http.HandlerFunc(s.handlePhoneRegisterResendPOST))
	// Public owner slug lookup (org/user) with namespace state + canonical public metadata.
	mux.Handle("GET /owners/{slug}", http.HandlerFunc(s.handleOwnerNamespaceInfoGET))

	// Email-based password reset and verification
	mux.Handle("POST /email/password/reset/request", http.HandlerFunc(s.handleEmailPasswordResetRequestPOST))
	mux.Handle("POST /email/password/reset/confirm", http.HandlerFunc(s.handleEmailPasswordResetConfirmPOST))
	mux.Handle("POST /email/password/reset/confirm-link", http.HandlerFunc(s.handleEmailPasswordResetConfirmLinkPOST))
	mux.Handle("POST /email/verify/request", http.HandlerFunc(s.handleEmailVerifyRequestPOST))
	mux.Handle("POST /email/verify/confirm", http.HandlerFunc(s.handleEmailVerifyConfirmPOST))
	mux.Handle("POST /email/verify/confirm-link", http.HandlerFunc(s.handleEmailVerifyConfirmLinkPOST))

	// Phone-based password reset and verification
	mux.Handle("POST /phone/verify/request", http.HandlerFunc(s.handlePhoneVerifyRequestPOST))
	mux.Handle("POST /phone/verify/confirm", http.HandlerFunc(s.handlePhoneVerifyConfirmPOST))
	mux.Handle("POST /phone/verify/confirm-link", http.HandlerFunc(s.handlePhoneVerifyConfirmLinkPOST))
	mux.Handle("POST /phone/password/reset/request", http.HandlerFunc(s.handlePhonePasswordResetRequestPOST))
	mux.Handle("POST /phone/password/reset/confirm", http.HandlerFunc(s.handlePhonePasswordResetConfirmPOST))

	required := Required(s.verifier)
	if strings.EqualFold(strings.TrimSpace(s.svc.Options().OrgMode), "multi") {
		mux.Handle("POST /token/org", required(http.HandlerFunc(s.handleAuthTokenOrgPOST)))
		// Org management endpoints are only exposed in org_mode=multi.
		mux.Handle("GET /orgs", required(http.HandlerFunc(s.handleOrgsListGET)))
		mux.Handle("POST /orgs", required(http.HandlerFunc(s.handleOrgsCreatePOST)))
		mux.Handle("GET /orgs/{org}", required(http.HandlerFunc(s.handleOrgsGetGET)))
		mux.Handle("POST /orgs/{org}/rename", required(http.HandlerFunc(s.handleOrgsRenamePOST)))
		mux.Handle("GET /orgs/{org}/members", required(http.HandlerFunc(s.handleOrgMembersGET)))
		mux.Handle("POST /orgs/{org}/members", required(http.HandlerFunc(s.handleOrgMembersPOST)))
		mux.Handle("DELETE /orgs/{org}/members", required(http.HandlerFunc(s.handleOrgMembersDELETE)))
		mux.Handle("GET /orgs/{org}/invites", required(http.HandlerFunc(s.handleOrgInvitesGET)))
		mux.Handle("POST /orgs/{org}/invites", required(http.HandlerFunc(s.handleOrgInvitesPOST)))
		mux.Handle("POST /orgs/{org}/invites/{invite_id}/revoke", required(http.HandlerFunc(s.handleOrgInviteRevokePOST)))
		mux.Handle("GET /org-invites", required(http.HandlerFunc(s.handleUserInvitesGET)))
		mux.Handle("POST /org-invites/{invite_id}/accept", required(http.HandlerFunc(s.handleOrgInviteAcceptPOST)))
		mux.Handle("POST /org-invites/{invite_id}/decline", required(http.HandlerFunc(s.handleOrgInviteDeclinePOST)))
		mux.Handle("GET /orgs/{org}/roles", required(http.HandlerFunc(s.handleOrgRolesGET)))
		mux.Handle("POST /orgs/{org}/roles", required(http.HandlerFunc(s.handleOrgRolesPOST)))
		mux.Handle("DELETE /orgs/{org}/roles", required(http.HandlerFunc(s.handleOrgRolesDELETE)))
		mux.Handle("GET /orgs/{org}/members/{user_id}/roles", required(http.HandlerFunc(s.handleOrgMemberRolesGET)))
		mux.Handle("POST /orgs/{org}/members/{user_id}/roles", required(http.HandlerFunc(s.handleOrgMemberRolesPOST)))
		mux.Handle("DELETE /orgs/{org}/members/{user_id}/roles", required(http.HandlerFunc(s.handleOrgMemberRolesDELETE)))
	}
	mux.Handle("DELETE /logout", required(http.HandlerFunc(s.handleLogoutDELETE)))
	mux.Handle("POST /reauth/password", required(http.HandlerFunc(s.handlePasswordReauthPOST)))
	mux.Handle("POST /user/password", required(http.HandlerFunc(s.handleUserPasswordPOST)))
	mux.Handle("GET /user/sessions", required(http.HandlerFunc(s.handleUserSessionsGET)))
	mux.Handle("DELETE /user/sessions/{id}", required(http.HandlerFunc(s.handleUserSessionDELETE)))
	mux.Handle("DELETE /user/sessions", required(http.HandlerFunc(s.handleUserSessionsDELETE)))
	mux.Handle("GET /user/me", required(http.HandlerFunc(s.handleUserMeGET)))
	mux.Handle("GET /user/bootstrap", required(http.HandlerFunc(s.handleUserBootstrapGET)))

	// User routes
	mux.Handle("PATCH /user/username", required(http.HandlerFunc(s.handleUserUsernamePATCH)))
	mux.Handle("POST /oidc/{provider}/link/start", required(http.HandlerFunc(s.handleOIDCLinkStartPOST)))
	mux.Handle("POST /oidc/{provider}/reauth/start", required(http.HandlerFunc(s.handleOIDCReauthStartPOST)))
	mux.Handle("POST /user/email/change/request", required(http.HandlerFunc(s.handleUserEmailChangeRequestPOST)))
	mux.Handle("POST /user/email/change/confirm", required(http.HandlerFunc(s.handleUserEmailChangeConfirmPOST)))
	mux.Handle("POST /user/email/change/resend", required(http.HandlerFunc(s.handleUserEmailChangeResendPOST)))
	mux.Handle("POST /user/phone/change/request", required(http.HandlerFunc(s.handleUserPhoneChangeRequestPOST)))
	mux.Handle("POST /user/phone/change/confirm", required(http.HandlerFunc(s.handleUserPhoneChangeConfirmPOST)))
	mux.Handle("POST /user/phone/change/resend", required(http.HandlerFunc(s.handleUserPhoneChangeResendPOST)))
	mux.Handle("PATCH /user/biography", required(http.HandlerFunc(s.handleUserBiographyPATCH)))
	mux.Handle("DELETE /user", required(http.HandlerFunc(s.handleUserDeleteDELETE)))
	mux.Handle("DELETE /user/providers/{provider}", required(http.HandlerFunc(s.handleUserUnlinkProviderDELETE)))

	// Two-Factor Authentication routes
	mux.Handle("GET /user/2fa", required(http.HandlerFunc(s.handleUser2FAStatusGET)))
	mux.Handle("POST /user/2fa/start-phone", required(http.HandlerFunc(s.handleUser2FAStartPhonePOST)))
	mux.Handle("POST /user/2fa/enable", required(http.HandlerFunc(s.handleUser2FAEnablePOST)))
	mux.Handle("POST /user/2fa/disable", required(http.HandlerFunc(s.handleUser2FADisablePOST)))
	mux.Handle("POST /user/2fa/regenerate-codes", required(http.HandlerFunc(s.handleUser2FARegenerateCodesPOST)))

	// Two-Factor Authentication routes (during login; no auth required)
	mux.Handle("POST /2fa/verify", http.HandlerFunc(s.handleUser2FAVerifyPOST))

	// Solana SIWS authentication routes
	mux.Handle("POST /solana/challenge", http.HandlerFunc(s.handleSolanaChallengePOST))
	mux.Handle("POST /solana/login", http.HandlerFunc(s.handleSolanaLoginPOST))
	mux.Handle("POST /solana/link", required(http.HandlerFunc(s.handleSolanaLinkPOST)))

	// Admin routes
	admin := func(h http.Handler) http.Handler { return required(RequireAdmin(s.svc.Postgres())(h)) }
	mux.Handle("POST /admin/roles/grant", admin(http.HandlerFunc(s.handleAdminRolesGrantPOST)))
	mux.Handle("POST /admin/roles/revoke", admin(http.HandlerFunc(s.handleAdminRolesRevokePOST)))
	mux.Handle("GET /admin/users", admin(http.HandlerFunc(s.handleAdminUsersListGET)))
	mux.Handle("GET /admin/users/{user_id}", admin(http.HandlerFunc(s.handleAdminUserGET)))
	mux.Handle("POST /admin/users/ban", admin(http.HandlerFunc(s.handleAdminUsersBanPOST)))
	mux.Handle("POST /admin/users/unban", admin(http.HandlerFunc(s.handleAdminUsersUnbanPOST)))
	mux.Handle("POST /admin/users/set-email", admin(http.HandlerFunc(s.handleAdminUsersSetEmailPOST)))
	mux.Handle("POST /admin/users/set-username", admin(http.HandlerFunc(s.handleAdminUsersSetUsernamePOST)))
	mux.Handle("POST /admin/users/set-password", admin(http.HandlerFunc(s.handleAdminUsersSetPasswordPOST)))
	// Hard-cut legacy endpoint naming.
	mux.Handle("POST /admin/users/toggle-active", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		notFound(w, "not_found")
	}))
	mux.Handle("DELETE /admin/users/{user_id}", admin(http.HandlerFunc(s.handleAdminUserDeleteDELETE)))
	mux.Handle("POST /admin/users/{user_id}/restore", admin(http.HandlerFunc(s.handleAdminUserRestorePOST)))
	mux.Handle("GET /admin/users/deleted", admin(http.HandlerFunc(s.handleAdminDeletedUsersListGET)))
	mux.Handle("GET /admin/users/{user_id}/signins", admin(http.HandlerFunc(s.handleAdminUserSigninsGET)))
	mux.Handle("POST /admin/users/{user_id}/sessions/revoke", admin(http.HandlerFunc(s.handleAdminUserSessionsRevokePOST)))
	mux.Handle("POST /admin/accounts/restrict", admin(http.HandlerFunc(s.handleAdminAccountsRestrictPOST)))
	mux.Handle("POST /admin/accounts/unrestrict", admin(http.HandlerFunc(s.handleAdminAccountsUnrestrictPOST)))
	mux.Handle("POST /admin/account/park", admin(http.HandlerFunc(s.handleAdminAccountParkPOST)))
	mux.Handle("POST /admin/account/claim", admin(http.HandlerFunc(s.handleAdminAccountClaimPOST)))
	// Hard-cut legacy org park/claim naming.
	mux.Handle("POST /admin/org/park", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		notFound(w, "not_found")
	}))
	mux.Handle("POST /admin/org/claim", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		notFound(w, "not_found")
	}))

	h := http.Handler(mux)
	h = LanguageMiddleware(s.langCfg)(h)
	return h
}
