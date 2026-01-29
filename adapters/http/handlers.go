package authhttp

import (
	"net/http"

	core "github.com/open-rails/authkit/core"
)

// JWKSHandler returns a handler for GET /.well-known/jwks.json.
func (s *Service) JWKSHandler() http.Handler { return JWKSHandler(s.svc) }

// APIHandler returns a handler that serves the JSON API routes under /auth/*.
// It is intended to be mounted under the host's mux/router at any prefix.
func (s *Service) APIHandler() http.Handler {
	if s == nil || s.svc == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serverErr(w, "authkit_not_initialized") })
	}
	if !core.IsDevEnvironment() {
		if s.svc.EphemeralMode() != core.EphemeralRedis {
			panic("authkit: redis-compatible ephemeral store is required in production")
		}
	}

	mux := http.NewServeMux()

	// Sessions + logout
	mux.Handle("POST /auth/token", http.HandlerFunc(s.handleAuthTokenPOST))
	mux.Handle("POST /auth/sessions/current", http.HandlerFunc(s.handleAuthSessionsCurrentPOST))

	// Registration + login
	mux.Handle("POST /auth/password/login", http.HandlerFunc(s.handlePasswordLoginPOST))
	mux.Handle("POST /auth/register", http.HandlerFunc(s.handleRegisterUnifiedPOST))
	mux.Handle("POST /auth/register/resend-email", http.HandlerFunc(s.handlePendingRegistrationResendPOST))
	mux.Handle("POST /auth/register/resend-phone", http.HandlerFunc(s.handlePhoneRegisterResendPOST))

	// Email-based password reset and verification
	mux.Handle("POST /auth/password/reset/request", http.HandlerFunc(s.handlePasswordResetRequestPOST))
	mux.Handle("POST /auth/password/reset/confirm", http.HandlerFunc(s.handlePasswordResetConfirmPOST))
	mux.Handle("POST /auth/password/reset/confirm-link", http.HandlerFunc(s.handlePasswordResetConfirmLinkPOST))
	mux.Handle("POST /auth/email/verify/request", http.HandlerFunc(s.handleEmailVerifyRequestPOST))
	mux.Handle("POST /auth/email/verify/confirm", http.HandlerFunc(s.handleEmailVerifyConfirmPOST))
	mux.Handle("POST /auth/email/verify/confirm-link", http.HandlerFunc(s.handleEmailVerifyConfirmLinkPOST))

	// Phone-based password reset and verification
	mux.Handle("POST /auth/phone/verify/request", http.HandlerFunc(s.handlePhoneVerifyRequestPOST))
	mux.Handle("POST /auth/phone/verify/confirm", http.HandlerFunc(s.handlePhoneVerifyConfirmPOST))
	mux.Handle("POST /auth/phone/password/reset/request", http.HandlerFunc(s.handlePhonePasswordResetRequestPOST))
	mux.Handle("POST /auth/phone/password/reset/confirm", http.HandlerFunc(s.handlePhonePasswordResetConfirmPOST))

	required := Required(s.svc)
	mux.Handle("DELETE /auth/logout", required(http.HandlerFunc(s.handleLogoutDELETE)))
	mux.Handle("POST /auth/user/password", required(http.HandlerFunc(s.handleUserPasswordPOST)))
	mux.Handle("GET /auth/user/sessions", required(http.HandlerFunc(s.handleUserSessionsGET)))
	mux.Handle("DELETE /auth/user/sessions/{id}", required(http.HandlerFunc(s.handleUserSessionDELETE)))
	mux.Handle("DELETE /auth/user/sessions", required(http.HandlerFunc(s.handleUserSessionsDELETE)))
	mux.Handle("GET /auth/user/me", required(http.HandlerFunc(s.handleUserMeGET)))

	// User routes
	mux.Handle("PATCH /auth/user/username", required(http.HandlerFunc(s.handleUserUsernamePATCH)))
	mux.Handle("POST /auth/oidc/{provider}/link/start", required(http.HandlerFunc(s.handleOIDCLinkStartPOST)))
	if _, ok := s.oidcProviders["discord"]; ok {
		mux.Handle("POST /auth/oauth/discord/link/start", required(http.HandlerFunc(s.handleDiscordLinkStartPOST)))
	}
	mux.Handle("POST /auth/user/email/change/request", required(http.HandlerFunc(s.handleUserEmailChangeRequestPOST)))
	mux.Handle("POST /auth/user/email/change/confirm", required(http.HandlerFunc(s.handleUserEmailChangeConfirmPOST)))
	mux.Handle("POST /auth/user/email/change/resend", required(http.HandlerFunc(s.handleUserEmailChangeResendPOST)))
	mux.Handle("POST /auth/user/phone/change/request", required(http.HandlerFunc(s.handleUserPhoneChangeRequestPOST)))
	mux.Handle("POST /auth/user/phone/change/confirm", required(http.HandlerFunc(s.handleUserPhoneChangeConfirmPOST)))
	mux.Handle("POST /auth/user/phone/change/resend", required(http.HandlerFunc(s.handleUserPhoneChangeResendPOST)))
	mux.Handle("PATCH /auth/user/biography", required(http.HandlerFunc(s.handleUserBiographyPATCH)))
	mux.Handle("DELETE /auth/user", required(http.HandlerFunc(s.handleUserDeleteDELETE)))
	mux.Handle("DELETE /auth/user/providers/{provider}", required(http.HandlerFunc(s.handleUserUnlinkProviderDELETE)))

	// Two-Factor Authentication routes
	mux.Handle("GET /auth/user/2fa", required(http.HandlerFunc(s.handleUser2FAStatusGET)))
	mux.Handle("POST /auth/user/2fa/start-phone", required(http.HandlerFunc(s.handleUser2FAStartPhonePOST)))
	mux.Handle("POST /auth/user/2fa/enable", required(http.HandlerFunc(s.handleUser2FAEnablePOST)))
	mux.Handle("POST /auth/user/2fa/disable", required(http.HandlerFunc(s.handleUser2FADisablePOST)))
	mux.Handle("POST /auth/user/2fa/regenerate-codes", required(http.HandlerFunc(s.handleUser2FARegenerateCodesPOST)))

	// Two-Factor Authentication routes (during login; no auth required)
	mux.Handle("POST /auth/2fa/verify", http.HandlerFunc(s.handleUser2FAVerifyPOST))

	// Solana SIWS authentication routes
	mux.Handle("POST /auth/solana/challenge", http.HandlerFunc(s.handleSolanaChallengePOST))
	mux.Handle("POST /auth/solana/login", http.HandlerFunc(s.handleSolanaLoginPOST))
	mux.Handle("POST /auth/solana/link", required(http.HandlerFunc(s.handleSolanaLinkPOST)))

	// Admin routes
	admin := func(h http.Handler) http.Handler { return required(RequireAdmin(s.svc.Postgres())(h)) }
	mux.Handle("POST /auth/admin/roles/grant", admin(http.HandlerFunc(s.handleAdminRolesGrantPOST)))
	mux.Handle("POST /auth/admin/roles/revoke", admin(http.HandlerFunc(s.handleAdminRolesRevokePOST)))
	mux.Handle("GET /auth/admin/users", admin(http.HandlerFunc(s.handleAdminUsersListGET)))
	mux.Handle("GET /auth/admin/users/{user_id}", admin(http.HandlerFunc(s.handleAdminUserGET)))
	mux.Handle("POST /auth/admin/users/ban", admin(http.HandlerFunc(s.handleAdminUsersBanPOST)))
	mux.Handle("POST /auth/admin/users/unban", admin(http.HandlerFunc(s.handleAdminUsersUnbanPOST)))
	mux.Handle("POST /auth/admin/users/set-email", admin(http.HandlerFunc(s.handleAdminUsersSetEmailPOST)))
	mux.Handle("POST /auth/admin/users/set-username", admin(http.HandlerFunc(s.handleAdminUsersSetUsernamePOST)))
	mux.Handle("POST /auth/admin/users/set-password", admin(http.HandlerFunc(s.handleAdminUsersSetPasswordPOST)))
	mux.Handle("POST /auth/admin/users/toggle-active", admin(http.HandlerFunc(s.handleAdminUserToggleActivePOST)))
	mux.Handle("DELETE /auth/admin/users/{user_id}", admin(http.HandlerFunc(s.handleAdminUserDeleteDELETE)))
	mux.Handle("POST /auth/admin/users/{user_id}/restore", admin(http.HandlerFunc(s.handleAdminUserRestorePOST)))
	mux.Handle("GET /auth/admin/users/deleted", admin(http.HandlerFunc(s.handleAdminDeletedUsersListGET)))
	mux.Handle("GET /auth/admin/users/{user_id}/signins", admin(http.HandlerFunc(s.handleAdminUserSigninsGET)))

	h := http.Handler(mux)
	h = LanguageMiddleware(s.langCfg)(h)
	return h
}
