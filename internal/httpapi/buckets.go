package httpapi

import (
	"maps"
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

	RLPasswordResetRequest = "password_reset_request"
	RLPasswordResetConfirm = "password_reset_confirm"
	// #312: one bucket per contact flow, whichever channel the identifier names.
	RLVerifyRequest   = "verify_request"
	RLVerifyConfirm   = "verify_confirm"
	RLMeContactChange = "me_contact_change"

	RLOIDCStart    = "oidc_start"
	RLOIDCCallback = "oidc_callback"

	// The authorization server (#430): its protocol endpoints, and the API the
	// SPA answers a pending sign-in request through.
	RLOAuthMetadata      = "oauth_metadata"
	RLOAuthAuthorize     = "oauth_authorize"
	RLOAuthToken         = "oauth_token"
	RLOAuthUserInfo      = "oauth_userinfo"
	RLOAuthEndSession    = "oauth_end_session"
	RLOAuthAuthorization = "oauth_authorization"

	// The SCIM service providers' reads; a directory sync pages through them.
	RLSCIMRead = "scim_read"
	// A directory's writes: a client provisioning its users one request each.
	RLSCIMWrite = "scim_write"

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

	RLCapabilitiesRead  = "capabilities_read"
	RLJWKSRead          = "jwks_read"
	RLMeGroupsRead      = "me_groups_read"
	RLMePermissionsRead = "me_permissions_read"
	// Group management: members, roles, and listing or revoking a group's
	// invitations and API keys. Creating either has its own bucket.
	RLGroupRead  = "group_read"
	RLGroupWrite = "group_write"

	// Every text message, whatever route sends it, against SMS pumping:
	// per destination number, account, client address and destination
	// country (SMSConfig).
	RLSMSNumber  = "sms_number"
	RLSMSAccount = "sms_account"
	RLSMSAddress = "sms_address"
	RLSMSCountry = "sms_country"

	// Solana SIWS authentication
	RLSolanaChallenge = "solana_challenge"
	RLSolanaLogin     = "solana_login"
	RLSolanaLink      = "solana_link"
)

// buckets are the default per-client budgets, grouped by what their routes do.
var buckets = map[string]ratelimit.Limit{
	// They check a secret.
	RLPasswordLogin:         {Limit: 20, Window: time.Hour},
	RLStepUpPassword:        {Limit: 20, Window: time.Hour},
	RLPasswordResetConfirm:  {Limit: 10, Window: 10 * time.Minute},
	RLPasswordlessConfirm:   {Limit: 10, Window: 10 * time.Minute},
	RLRegisterAbandon:       {Limit: 10, Window: time.Hour, Cooldown: time.Minute},
	RLVerifyConfirm:         {Limit: 10, Window: 10 * time.Minute},
	RLTokenRefresh:          {Limit: 30, Window: time.Minute},
	RL2FAVerify:             {Limit: 10, Window: 10 * time.Minute},
	RL2FAEnable:             {Limit: 6, Window: time.Hour},
	RLPasskeyLogin:          {Limit: 20, Window: time.Hour},
	RLDeviceKeyEnrollFinish: {Limit: 10, Window: 10 * time.Minute},
	RLDeviceKeyLoginFinish:  {Limit: 30, Window: 10 * time.Minute},
	RLInviteRedeem:          {Limit: 60, Window: time.Hour},
	RLOIDCCallback:          {Limit: 60, Window: 10 * time.Minute},
	RLSolanaLogin:           {Limit: 20, Window: 10 * time.Minute},
	RLOAuthToken:            {Limit: 120, Window: time.Minute},
	RLSolanaLink:            {Limit: 12, Window: time.Hour},
	RLStepUpCode:            {Limit: 10, Window: 10 * time.Minute},
	RLStepUpSignature:       {Limit: 20, Window: 10 * time.Minute},

	// They send an email or SMS. /register and /passwordless/start also check
	// an account invitation when one is presented.
	RLRegisterCreate:       {Limit: 6, Window: time.Hour, Cooldown: time.Minute},
	RLPasswordlessStart:    {Limit: 6, Window: time.Hour, Cooldown: time.Minute},
	RLPasswordResetRequest: {Limit: 6, Window: time.Hour, Cooldown: time.Minute},
	RLVerifyRequest:        {Limit: 6, Window: time.Hour, Cooldown: time.Minute},
	RLMeContactChange:      {Limit: 6, Window: time.Hour, Cooldown: time.Minute},
	RLDeviceKeyEnrollBegin: {Limit: 6, Window: time.Hour, Cooldown: time.Minute},
	RL2FASetupSMS:          {Limit: 3, Window: 10 * time.Minute},
	RL2FASetupEmail:        {Limit: 3, Window: 10 * time.Minute},
	RLInviteCreate:         {Limit: 20, Window: time.Hour, Cooldown: time.Minute},
	RLStepUp2FASend:        {Limit: 6, Window: 10 * time.Minute},
	RLStepUpCodeSend:       {Limit: 6, Window: 10 * time.Minute},
	// Every text message, beside its route's bucket.
	RLSMSNumber:  {Limit: 10, Window: time.Hour},
	RLSMSAccount: {Limit: 10, Window: time.Hour},
	RLSMSAddress: {Limit: 20, Window: time.Hour},
	RLSMSCountry: {Limit: 1000, Window: time.Hour},

	// They issue a secret. An OIDC start issues the flow's state.
	RL2FASetupTOTP:       {Limit: 6, Window: time.Hour},
	RL2FARegenerateCodes: {Limit: 3, Window: time.Hour},
	RLAPIKeyCreate:       {Limit: 20, Window: time.Hour},
	RLOIDCStart:          {Limit: 30, Window: 10 * time.Minute},
	RLOAuthAuthorize:     {Limit: 60, Window: 10 * time.Minute},
	RLOAuthAuthorization: {Limit: 60, Window: 10 * time.Minute},

	// Reads, and changes that check, issue and send nothing. A challenge the
	// caller must sign is not a secret; a password the account routes accept
	// inline is checked under RLStepUpPassword.
	RLRegisterAvailability: {Limit: 120, Window: time.Minute},
	RLPasskeyRegister:      {Limit: 12, Window: time.Hour},
	RLDeviceKeyLoginBegin:  {Limit: 30, Window: 10 * time.Minute},
	RLDeviceKeyManage:      {Limit: 30, Window: 10 * time.Minute},
	RLSessionLogout:        {Limit: 60, Window: 10 * time.Minute},
	RLSessionList:          {Limit: 120, Window: time.Minute},
	RLSessionRevoke:        {Limit: 60, Window: 10 * time.Minute},
	RLSessionRevokeAll:     {Limit: 20, Window: time.Hour},
	RLMePasswordChange:     {Limit: 6, Window: time.Hour},
	RLMeRead:               {Limit: 120, Window: time.Minute},
	RLUsersRead:            {Limit: 120, Window: time.Minute},
	RLMeUpdate:             {Limit: 24, Window: time.Hour},
	RLMeDelete:             {Limit: 6, Window: time.Hour},
	RLMeProviderUnlink:     {Limit: 12, Window: time.Hour},
	RLSolanaChallenge:      {Limit: 30, Window: 10 * time.Minute},
	RLStepUpChallenge:      {Limit: 30, Window: 10 * time.Minute},
	RL2FADisable:           {Limit: 6, Window: time.Hour},
	RLAdminRead:            {Limit: 600, Window: time.Hour},
	RLAdminWrite:           {Limit: 30, Window: time.Hour},
	RLCapabilitiesRead:     {Limit: 120, Window: time.Minute},
	RLMeGroupsRead:         {Limit: 120, Window: time.Minute},
	RLMePermissionsRead:    {Limit: 120, Window: time.Minute},
	// API keys and applications manage groups too, many calls from one address.
	RLGroupRead:  {Limit: 300, Window: time.Minute},
	RLGroupWrite: {Limit: 120, Window: time.Minute},
	// Verifiers behind one address each poll JWKS.
	RLJWKSRead:      {Limit: 600, Window: time.Minute},
	RLOAuthMetadata: {Limit: 600, Window: time.Minute},
	RLOAuthUserInfo: {Limit: 300, Window: time.Minute},
	RLSCIMRead:      {Limit: 600, Window: time.Minute},
	RLSCIMWrite:     {Limit: 1200, Window: time.Minute},
	// A logout only ends a session the hint names.
	RLOAuthEndSession: {Limit: 60, Window: 10 * time.Minute},
}

// DefaultRateLimits returns AuthKit's built-in per-endpoint rate limits, per
// client IP: every route has a bucket, and "default" applies to any bucket
// not listed. Hosts overlay them with HTTPConfig.RateLimits.
func DefaultRateLimits() map[string]ratelimit.Limit {
	out := map[string]ratelimit.Limit{"default": {Limit: 120, Window: time.Minute}}
	maps.Copy(out, buckets)
	return out
}
