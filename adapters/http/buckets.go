package authhttp

// Bucket names used by authkit endpoints.
const (
	// 2FA-specific rate limit buckets
	RL2FAStartPhone      = "auth_2fa_start_phone"
	RL2FAEnable          = "auth_2fa_enable"
	RL2FADisable         = "auth_2fa_disable"
	RL2FARegenerateCodes = "auth_2fa_regenerate_codes"
	RL2FAVerify          = "auth_2fa_verify"

	RLAuthToken               = "auth_token"
	RLAuthRegister            = "auth_register"
	RLAuthRegisterResendEmail = "auth_register_resend_email"
	RLAuthRegisterResendPhone = "auth_register_resend_phone"
	RLPasswordLogin           = "auth_password_login"
	RLAuthLogout              = "auth_logout"
	RLAuthSessionsCurrent     = "auth_sessions_current"
	RLAuthSessionsList        = "auth_sessions_list"
	RLAuthSessionsRevoke      = "auth_sessions_revoke"
	RLAuthSessionsRevokeAll   = "auth_sessions_revoke_all"

	RLPasswordResetRequest = "auth_pwd_reset_request"
	RLPasswordResetConfirm = "auth_pwd_reset_confirm"
	RLEmailVerifyRequest   = "auth_email_verify_request"
	RLEmailVerifyConfirm   = "auth_email_verify_confirm"
	RLPhoneVerifyRequest   = "auth_phone_verify_request"

	RLOIDCStart    = "auth_oidc_start"
	RLOIDCCallback = "auth_oidc_callback"

	RLUserPasswordChange = "auth_user_password_change"
	RLUserMe             = "auth_user_me"
	RLUserUpdateUsername = "auth_user_update_username"
	RLUserUpdateEmail    = "auth_user_update_email"

	RLUserEmailChangeRequest = "auth_user_email_change_request"
	RLUserEmailChangeConfirm = "auth_user_email_change_confirm"
	RLUserEmailChangeResend  = "auth_user_email_change_resend"

	RLUserPhoneChangeRequest = "auth_user_phone_change_request"
	RLUserPhoneChangeConfirm = "auth_user_phone_change_confirm"
	RLUserPhoneChangeResend  = "auth_user_phone_change_resend"

	RLUserDelete         = "auth_user_delete"
	RLUserUnlinkProvider = "auth_user_unlink_provider"

	RLAdminRolesGrant            = "auth_admin_roles_grant"
	RLAdminRolesRevoke           = "auth_admin_roles_revoke"
	RLAdminUserSessionsList      = "auth_admin_user_sessions_list"
	RLAdminUserSessionsRevoke    = "auth_admin_user_sessions_revoke"
	RLAdminUserSessionsRevokeAll = "auth_admin_user_sessions_revoke_all"

	// Solana SIWS authentication
	RLSolanaChallenge = "auth_solana_challenge"
	RLSolanaLogin     = "auth_solana_login"
	RLSolanaLink      = "auth_solana_link"
)
