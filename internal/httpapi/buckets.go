package httpapi

import (
	"time"

	"github.com/open-rails/authkit/internal/ratelimit"
)

// Bucket names key HTTPConfig.RateLimits and name the action a rate_limited
// error reports. Each is <area>_<action>: the route family as its path spells
// it (me, session, 2fa, step_up, device_key, …), then what the route does.
const (
	// 2FA-specific rate limit buckets
	RL2FASetupSMS        = "2fa_setup_sms"
	RL2FASetupTOTP       = "2fa_setup_totp"
	RL2FASetupEmail      = "2fa_setup_email"
	RL2FAEnable          = "2fa_enable"
	RL2FADisable         = "2fa_disable"
	RL2FARegenerateCodes = "2fa_regenerate_codes"
	RL2FAVerify          = "2fa_verify"

	RLTokenRefresh          = "token_refresh"
	RLRegisterCreate        = "register_create"
	RLRegisterAvailability  = "register_availability"
	RLRegisterAbandon       = "register_abandon"
	RLInviteCreate          = "invite_create"
	RLInviteRedeem          = "invite_redeem"
	RLAPIKeyCreate          = "api_key_create"
	RLPasswordLogin         = "password_login"
	RLStepUpPassword        = "step_up_password"
	RLPasswordlessStart     = "passwordless_start"
	RLPasswordlessConfirm   = "passwordless_confirm"
	RLPasskeyRegister       = "passkey_register"
	RLPasskeyLogin          = "passkey_login"
	RLDeviceKeyEnrollBegin  = "device_key_enroll_begin"
	RLDeviceKeyEnrollFinish = "device_key_enroll_finish"
	RLDeviceKeyLoginBegin   = "device_key_login_begin"
	RLDeviceKeyLoginFinish  = "device_key_login_finish"
	RLDeviceKeyManage       = "device_key_manage"
	RLSessionLogout         = "session_logout"
	RLSessionList           = "session_list"
	RLSessionRevoke         = "session_revoke"
	RLSessionRevokeAll      = "session_revoke_all"

	// #261 delegated-token mint (authenticated; bounds signing cost per IP).
	RLDelegatedTokenMint = "delegated_token_mint"

	RLPasswordResetRequest = "password_reset_request"
	RLPasswordResetConfirm = "password_reset_confirm"
	// #312: one bucket per contact flow, whichever channel the identifier names.
	RLVerifyRequest   = "verify_request"
	RLVerifyConfirm   = "verify_confirm"
	RLMeContactChange = "me_contact_change"

	RLOIDCStart    = "oidc_start"
	RLOIDCCallback = "oidc_callback"

	RLMePasswordChange = "me_password_change"
	RLMeRead           = "me_read"
	RLMeUpdate         = "me_update"
	RLStepUp2FASend    = "step_up_2fa_send"
	// Step-up by a code to a proven address, a wallet or a passkey.
	RLStepUpCodeSend  = "step_up_code_send"
	RLStepUpCode      = "step_up_code"
	RLStepUpChallenge = "step_up_challenge"
	RLStepUpSignature = "step_up_signature"

	RLMeDelete         = "me_delete"
	RLMeProviderUnlink = "me_provider_unlink"

	RLUsersRead = "users_read"

	RLAdminRead  = "admin_read"
	RLAdminWrite = "admin_write"

	// Solana SIWS authentication
	RLSolanaChallenge = "solana_challenge"
	RLSolanaLogin     = "solana_login"
	RLSolanaLink      = "solana_link"
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
	RLStepUpPassword:        {limit: lim{Limit: 20, Window: time.Hour}},
	RLPasswordResetConfirm:  {limit: lim{Limit: 10, Window: 10 * time.Minute}},
	RLPasswordlessConfirm:   {limit: lim{Limit: 10, Window: 10 * time.Minute}},
	RLRegisterAbandon:       {limit: lim{Limit: 10, Window: time.Hour, Cooldown: time.Minute}},
	RLVerifyConfirm:         {limit: lim{Limit: 10, Window: 10 * time.Minute}},
	RLTokenRefresh:          {limit: lim{Limit: 30, Window: time.Minute}},
	RL2FAVerify:             {limit: lim{Limit: 10, Window: 10 * time.Minute}},
	RL2FAEnable:             {limit: lim{Limit: 6, Window: time.Hour}},
	RLPasskeyLogin:          {limit: lim{Limit: 20, Window: time.Hour}},
	RLDeviceKeyEnrollFinish: {limit: lim{Limit: 10, Window: 10 * time.Minute}},
	RLDeviceKeyLoginFinish:  {limit: lim{Limit: 30, Window: 10 * time.Minute}},
	RLInviteRedeem:          {limit: lim{Limit: 60, Window: time.Hour}},
	RLOIDCCallback:          {limit: lim{Limit: 60, Window: 10 * time.Minute}},
	RLSolanaLogin:           {limit: lim{Limit: 20, Window: 10 * time.Minute}},
	RLSolanaLink:            {limit: lim{Limit: 12, Window: time.Hour}},
	RLStepUpCode:            {limit: lim{Limit: 10, Window: 10 * time.Minute}},
	RLStepUpSignature:       {limit: lim{Limit: 20, Window: 10 * time.Minute}},

	// They send an email or SMS. /register and /passwordless/start also check
	// an account invitation when one is presented.
	RLRegisterCreate:       {limit: lim{Limit: 6, Window: time.Hour, Cooldown: time.Minute}},
	RLPasswordlessStart:    {limit: lim{Limit: 6, Window: time.Hour, Cooldown: time.Minute}},
	RLPasswordResetRequest: {limit: lim{Limit: 6, Window: time.Hour, Cooldown: time.Minute}},
	RLVerifyRequest:        {limit: lim{Limit: 6, Window: time.Hour, Cooldown: time.Minute}},
	RLMeContactChange:      {limit: lim{Limit: 6, Window: time.Hour, Cooldown: time.Minute}},
	RLDeviceKeyEnrollBegin: {limit: lim{Limit: 6, Window: time.Hour, Cooldown: time.Minute}},
	RL2FASetupSMS:          {limit: lim{Limit: 3, Window: 10 * time.Minute}},
	RL2FASetupEmail:        {limit: lim{Limit: 3, Window: 10 * time.Minute}},
	RLInviteCreate:         {limit: lim{Limit: 20, Window: time.Hour, Cooldown: time.Minute}},
	RLStepUp2FASend:        {limit: lim{Limit: 6, Window: 10 * time.Minute}},
	RLStepUpCodeSend:       {limit: lim{Limit: 6, Window: 10 * time.Minute}},

	// They issue a secret. An OIDC start issues the flow's state.
	RL2FASetupTOTP:       {limit: lim{Limit: 6, Window: time.Hour}},
	RL2FARegenerateCodes: {limit: lim{Limit: 3, Window: time.Hour}},
	RLAPIKeyCreate:       {limit: lim{Limit: 20, Window: time.Hour}},
	RLDelegatedTokenMint: {limit: lim{Limit: 60, Window: time.Minute}},
	RLOIDCStart:          {limit: lim{Limit: 30, Window: 10 * time.Minute}},

	// Reads, and changes that check, issue and send nothing. A challenge the
	// caller must sign is not a secret; a password the account routes accept
	// inline is checked under RLStepUpPassword.
	RLRegisterAvailability: {limit: lim{Limit: 120, Window: time.Minute}, failOpen: true},
	RLPasskeyRegister:      {limit: lim{Limit: 12, Window: time.Hour}, failOpen: true},
	RLDeviceKeyLoginBegin:  {limit: lim{Limit: 30, Window: 10 * time.Minute}, failOpen: true},
	RLDeviceKeyManage:      {limit: lim{Limit: 30, Window: 10 * time.Minute}, failOpen: true},
	RLSessionLogout:        {limit: lim{Limit: 60, Window: 10 * time.Minute}, failOpen: true},
	RLSessionList:          {limit: lim{Limit: 120, Window: time.Minute}, failOpen: true},
	RLSessionRevoke:        {limit: lim{Limit: 60, Window: 10 * time.Minute}, failOpen: true},
	RLSessionRevokeAll:     {limit: lim{Limit: 20, Window: time.Hour}, failOpen: true},
	RLMePasswordChange:     {limit: lim{Limit: 6, Window: time.Hour}, failOpen: true},
	RLMeRead:               {limit: lim{Limit: 120, Window: time.Minute}, failOpen: true},
	RLUsersRead:            {limit: lim{Limit: 120, Window: time.Minute}, failOpen: true},
	RLMeUpdate:             {limit: lim{Limit: 24, Window: time.Hour}, failOpen: true},
	RLMeDelete:             {limit: lim{Limit: 6, Window: time.Hour}, failOpen: true},
	RLMeProviderUnlink:     {limit: lim{Limit: 12, Window: time.Hour}, failOpen: true},
	RLSolanaChallenge:      {limit: lim{Limit: 30, Window: 10 * time.Minute}, failOpen: true},
	RLStepUpChallenge:      {limit: lim{Limit: 30, Window: 10 * time.Minute}, failOpen: true},
	RL2FADisable:           {limit: lim{Limit: 6, Window: time.Hour}, failOpen: true},
	RLAdminRead:            {limit: lim{Limit: 600, Window: time.Hour}, failOpen: true},
	RLAdminWrite:           {limit: lim{Limit: 30, Window: time.Hour}, failOpen: true},
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
