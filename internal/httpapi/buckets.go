package httpapi

import (
	"time"

	"github.com/open-rails/authkit/internal/ratelimit"
)

// Bucket names used by authkit endpoints; they key HTTPConfig.RateLimits.
const (
	// 2FA-specific rate limit buckets
	RL2FAStartPhone      = "auth_2fa_start_phone"
	RL2FAStartTOTP       = "auth_2fa_start_totp"
	RL2FAStartEmail      = "auth_2fa_start_email"
	RL2FAEnable          = "auth_2fa_enable"
	RL2FADisable         = "auth_2fa_disable"
	RL2FARegenerateCodes = "auth_2fa_regenerate_codes"
	RL2FAVerify          = "auth_2fa_verify"

	RLAuthToken                = "auth_token"
	RLAuthRegister             = "auth_register"
	RLAuthRegisterAvailability = "auth_register_availability"
	RLAuthRegisterAbandon      = "auth_register_abandon"
	RLInviteCreate             = "auth_invite_create"
	RLInviteRedeem             = "auth_invite_redeem"
	RLAPIKeyMint               = "auth_api_key_mint"
	RLPasswordLogin            = "auth_password_login"
	RLPasswordStepUp           = "auth_password_step_up"
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
	RLAuthSessionsList         = "auth_sessions_list"
	RLAuthSessionsRevoke       = "auth_sessions_revoke"
	RLAuthSessionsRevokeAll    = "auth_sessions_revoke_all"

	// #261 delegated-token mint (authenticated; bounds signing cost per IP).
	RLDelegatedTokenMint = "delegated_token_mint"

	RLPasswordResetRequest = "auth_pwd_reset_request"
	RLPasswordResetConfirm = "auth_pwd_reset_confirm"
	// #312: one bucket per contact flow, whichever channel the identifier names.
	RLVerifyRequest        = "auth_verify_request"
	RLVerifyConfirm        = "auth_verify_confirm"
	RLContactChangeRequest = "auth_contact_change_request"

	RLOIDCStart    = "auth_oidc_start"
	RLOIDCCallback = "auth_oidc_callback"

	RLUserPasswordChange    = "auth_user_password_change"
	RLUserMe                = "auth_user_me"
	RLUserUpdateUsername    = "auth_user_update_username"
	RLUserPreferredLanguage = "auth_user_preferred_language"

	RLUserDelete         = "auth_user_delete"
	RLUserUnlinkProvider = "auth_user_unlink_provider"

	RLAdminUserSessionsList = "auth_admin_user_sessions_list"
	// The admin session route revokes ALL of a user's sessions; there is no
	// single-session admin revoke, so no RLAdminUserSessionsRevoke bucket.
	RLAdminUserSessionsRevokeAll = "auth_admin_user_sessions_revoke_all"

	// Solana SIWS authentication
	RLSolanaChallenge = "auth_solana_challenge"
	RLSolanaLogin     = "auth_solana_login"
	RLSolanaLink      = "auth_solana_link"
)

// bucket is a rate-limit budget: its default per-client limit and what its
// requests get when the limiter's backend fails. A bucket fails closed: its
// requests are refused, so an outage never lifts the budget in front of a
// secret check or issue (a password, one-time or backup code, a link, refresh,
// invite or OIDC state token, an API key, or a signature over a challenge) or
// a message sent by email or SMS. Only a bucket whose routes do none of that
// sets failOpen, and stays up through the outage.
type bucket struct {
	limit    ratelimit.Limit
	failOpen bool
}

type lim = ratelimit.Limit

var buckets = map[string]bucket{
	// They check a secret.
	RLPasswordLogin:         {limit: lim{Limit: 20, Window: time.Hour}},
	RLPasswordStepUp:        {limit: lim{Limit: 20, Window: time.Hour}},
	RLPasswordResetConfirm:  {limit: lim{Limit: 10, Window: 10 * time.Minute}},
	RLPasswordlessConfirm:   {limit: lim{Limit: 10, Window: 10 * time.Minute}},
	RLAuthRegisterAbandon:   {limit: lim{Limit: 10, Window: time.Hour, Cooldown: time.Minute}},
	RLVerifyConfirm:         {limit: lim{Limit: 10, Window: 10 * time.Minute}},
	RLAuthToken:             {limit: lim{Limit: 30, Window: time.Minute}},
	RL2FAVerify:             {limit: lim{Limit: 10, Window: 10 * time.Minute}},
	RL2FAEnable:             {limit: lim{Limit: 6, Window: time.Hour}},
	RLPasskeyLogin:          {limit: lim{Limit: 20, Window: time.Hour}},
	RLDeviceKeyEnrollFinish: {limit: lim{Limit: 10, Window: 10 * time.Minute}},
	RLDeviceKeyLoginFinish:  {limit: lim{Limit: 30, Window: 10 * time.Minute}},
	RLInviteRedeem:          {limit: lim{Limit: 60, Window: time.Hour}},
	RLOIDCCallback:          {limit: lim{Limit: 60, Window: 10 * time.Minute}},
	RLSolanaLogin:           {limit: lim{Limit: 20, Window: 10 * time.Minute}},
	RLSolanaLink:            {limit: lim{Limit: 12, Window: time.Hour}},

	// They send an email or SMS. /register and /passwordless/start also check
	// an account invitation when one is presented.
	RLAuthRegister:         {limit: lim{Limit: 6, Window: time.Hour, Cooldown: time.Minute}},
	RLPasswordlessStart:    {limit: lim{Limit: 6, Window: time.Hour, Cooldown: time.Minute}},
	RLPasswordResetRequest: {limit: lim{Limit: 6, Window: time.Hour, Cooldown: time.Minute}},
	RLVerifyRequest:        {limit: lim{Limit: 6, Window: time.Hour, Cooldown: time.Minute}},
	RLContactChangeRequest: {limit: lim{Limit: 6, Window: time.Hour, Cooldown: time.Minute}},
	RLDeviceKeyEnrollBegin: {limit: lim{Limit: 6, Window: time.Hour, Cooldown: time.Minute}},
	RL2FAStartPhone:        {limit: lim{Limit: 3, Window: 10 * time.Minute}},
	RL2FAStartEmail:        {limit: lim{Limit: 3, Window: 10 * time.Minute}},
	RLInviteCreate:         {limit: lim{Limit: 20, Window: time.Hour, Cooldown: time.Minute}},

	// They issue a secret. An OIDC start issues the flow's state.
	RL2FAStartTOTP:       {limit: lim{Limit: 6, Window: time.Hour}},
	RL2FARegenerateCodes: {limit: lim{Limit: 3, Window: time.Hour}},
	RLAPIKeyMint:         {limit: lim{Limit: 20, Window: time.Hour}},
	RLDelegatedTokenMint: {limit: lim{Limit: 60, Window: time.Minute}},
	RLOIDCStart:          {limit: lim{Limit: 30, Window: 10 * time.Minute}},

	// Reads, and changes that check, issue and send nothing. A challenge the
	// caller must sign is not a secret; a password the account routes accept
	// inline is checked under RLPasswordStepUp.
	RLAuthRegisterAvailability:   {limit: lim{Limit: 120, Window: time.Minute}, failOpen: true},
	RLPasskeyRegister:            {limit: lim{Limit: 12, Window: time.Hour}, failOpen: true},
	RLDeviceKeyLoginBegin:        {limit: lim{Limit: 30, Window: 10 * time.Minute}, failOpen: true},
	RLDeviceKeysManage:           {limit: lim{Limit: 30, Window: 10 * time.Minute}, failOpen: true},
	RLAuthLogout:                 {limit: lim{Limit: 60, Window: 10 * time.Minute}, failOpen: true},
	RLAuthSessionsList:           {limit: lim{Limit: 120, Window: time.Minute}, failOpen: true},
	RLAuthSessionsRevoke:         {limit: lim{Limit: 60, Window: 10 * time.Minute}, failOpen: true},
	RLAuthSessionsRevokeAll:      {limit: lim{Limit: 20, Window: time.Hour}, failOpen: true},
	RLUserPasswordChange:         {limit: lim{Limit: 6, Window: time.Hour}, failOpen: true},
	RLUserMe:                     {limit: lim{Limit: 120, Window: time.Minute}, failOpen: true},
	RLUserUpdateUsername:         {limit: lim{Limit: 12, Window: time.Hour}, failOpen: true},
	RLUserPreferredLanguage:      {limit: lim{Limit: 24, Window: time.Hour}, failOpen: true},
	RLUserDelete:                 {limit: lim{Limit: 6, Window: time.Hour}, failOpen: true},
	RLUserUnlinkProvider:         {limit: lim{Limit: 12, Window: time.Hour}, failOpen: true},
	RLSolanaChallenge:            {limit: lim{Limit: 30, Window: 10 * time.Minute}, failOpen: true},
	RL2FADisable:                 {limit: lim{Limit: 6, Window: time.Hour}, failOpen: true},
	RLAdminUserSessionsList:      {limit: lim{Limit: 600, Window: time.Hour}, failOpen: true},
	RLAdminUserSessionsRevokeAll: {limit: lim{Limit: 30, Window: time.Hour}, failOpen: true},
}

// DefaultRateLimits returns AuthKit's built-in per-endpoint rate limits, per
// client IP; "default" applies to any bucket not listed. Hosts overlay them
// with HTTPConfig.RateLimits or replace the limiter.
func DefaultRateLimits() map[string]ratelimit.Limit {
	out := map[string]ratelimit.Limit{"default": {Limit: 120, Window: time.Minute}}
	for name, b := range buckets {
		out[name] = b.limit
	}
	return out
}
