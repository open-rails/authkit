package authhttp

// Bucket names used by authkit endpoints.
const (
	// 2FA-specific rate limit buckets
	RL2FAStartPhone      = "auth_2fa_start_phone"
	RL2FAStartTOTP       = "auth_2fa_start_totp"
	RL2FAEnable          = "auth_2fa_enable"
	RL2FADisable         = "auth_2fa_disable"
	RL2FARegenerateCodes = "auth_2fa_regenerate_codes"
	RL2FAVerify          = "auth_2fa_verify"

	RLAuthToken                = "auth_token"
	RLAuthRegister             = "auth_register"
	RLAuthRegisterAvailability = "auth_register_availability"
	RLAuthRegisterResendEmail  = "auth_register_resend_email"
	RLAuthRegisterResendPhone  = "auth_register_resend_phone"
	RLAuthRegisterAbandon      = "auth_register_abandon"
	RLInviteCreate             = "auth_invite_create"
	RLPasswordLogin            = "auth_password_login"
	RLPasswordlessStart        = "auth_passwordless_start"
	RLPasswordlessConfirm      = "auth_passwordless_confirm"
	RLPasskeyRegister          = "auth_passkey_register"
	RLPasskeyLogin             = "auth_passkey_login"
	RLDeviceKeyEnrollBegin     = "auth_device_key_enroll_begin"
	RLDeviceKeyEnrollFinish    = "auth_device_key_enroll_finish"
	RLDeviceKeyLoginBegin      = "auth_device_key_login_begin"
	RLDeviceKeyLoginFinish     = "auth_device_key_login_finish"
	RLDeviceKeysManage         = "auth_device_keys_manage"
	RLAuthLogout               = "auth_logout"
	RLAuthSessionsCurrent      = "auth_sessions_current"
	RLAuthSessionsList         = "auth_sessions_list"
	RLAuthSessionsRevoke       = "auth_sessions_revoke"
	RLAuthSessionsRevokeAll    = "auth_sessions_revoke_all"

	// #264 application self-registration (per-IP AND per-domain/slug keys).
	RLApplicationRegister = "application_register"
	RLApplicationRotate   = "application_rotate"
	// #264 anti-squat velocity: group settings (slug rename IS a claim),
	// keyed per-IP and per-user.
	RLGroupSettings = "group_settings"
	// #263 anti-squat velocity: generated persona-instance creation (a create
	// IS a claim), keyed per-IP and per-user.
	RLGroupCreate = "group_create"

	// #261 delegated-token mint (authenticated; bounds signing cost per IP).
	RLDelegatedTokenMint = "delegated_token_mint"

	RLPasswordResetRequest = "auth_pwd_reset_request"
	RLPasswordResetConfirm = "auth_pwd_reset_confirm"
	RLEmailVerifyRequest   = "auth_email_verify_request"
	RLEmailVerifyConfirm   = "auth_email_verify_confirm"
	RLPhoneVerifyRequest   = "auth_phone_verify_request"
	RLPhoneVerifyConfirm   = "auth_phone_verify_confirm"

	RLOIDCStart    = "auth_oidc_start"
	RLOIDCCallback = "auth_oidc_callback"

	RLUserPasswordChange    = "auth_user_password_change"
	RLUserMe                = "auth_user_me"
	RLUserMetadata          = "auth_user_metadata"
	RLUserUpdateUsername    = "auth_user_update_username"
	RLUserPreferredLanguage = "auth_user_preferred_language"
	RLUserUpdateEmail       = "auth_user_update_email"

	RLUserEmailChangeRequest = "auth_user_email_change_request"
	RLUserEmailChangeConfirm = "auth_user_email_change_confirm"
	RLUserEmailChangeResend  = "auth_user_email_change_resend"
	RLUserEmailChangeCancel  = "auth_user_email_change_cancel"

	RLUserPhoneChangeRequest = "auth_user_phone_change_request"
	RLUserPhoneChangeConfirm = "auth_user_phone_change_confirm"
	RLUserPhoneChangeResend  = "auth_user_phone_change_resend"
	RLUserPhoneChangeCancel  = "auth_user_phone_change_cancel"

	RLUserDelete         = "auth_user_delete"
	RLUserUnlinkProvider = "auth_user_unlink_provider"

	RLAdminRolesGrant       = "auth_admin_roles_grant"
	RLAdminRolesRevoke      = "auth_admin_roles_revoke"
	RLAdminUserSessionsList = "auth_admin_user_sessions_list"
	// The admin session route revokes ALL of a user's sessions; there is no
	// single-session admin revoke, so no RLAdminUserSessionsRevoke bucket.
	RLAdminUserSessionsRevokeAll = "auth_admin_user_sessions_revoke_all"

	// Solana SIWS authentication
	RLSolanaChallenge = "auth_solana_challenge"
	RLSolanaLogin     = "auth_solana_login"
	RLSolanaLink      = "auth_solana_link"
)
