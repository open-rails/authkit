package httpapi

import (
	"encoding/json"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/naming"
)

// The HTTP-only wire shapes: request bodies, query strings and the responses
// that have no iam type. Domain results are the iam types themselves. The
// route catalog names each route's shapes, and internal/cmd/contract
// generates openapi.json and the TypeScript wire types from them.
//
// Conventions (catalog_test.go enforces them): every response field is always
// present; an unset value is null (a pointer), a list is [] and a map {}; no
// omitempty; times are time.Time, written in UTC.

// PageQuery is ?cursor= and ?limit= of every paged list. The cursor is opaque;
// limit is 1-500 (default 50).
type PageQuery struct {
	Cursor string `query:"cursor"`
	Limit  string `query:"limit"`
}

// Requests.

type TokenRefreshRequest struct {
	GrantType string `json:"grant_type"`
	// RefreshToken is empty on cookie mounts, where the cookie carries it.
	RefreshToken string `json:"refresh_token"`
}

type PasswordLoginRequest struct {
	Identifier string `json:"identifier"` // email, phone number or username
	Password   string `json:"password"`
}

type TokenRequest struct {
	Token string `json:"token"`
}

type PasswordlessStartRequest struct {
	Identifier         string `json:"identifier"`
	Mode               string `json:"mode"`
	ReturnTo           string `json:"return_to"`
	PreferredLanguage  string `json:"preferred_language"`
	AccountInviteToken string `json:"account_invite_token"`
}

type CodeOrLinkRequest struct {
	Identifier string `json:"identifier"`
	Code       string `json:"code"`
	Token      string `json:"token"`
}

type DeviceKeyEnrollBeginRequest struct {
	Email     string `json:"email"`
	PublicKey string `json:"public_key"`
	Label     string `json:"label"`
}

type DeviceKeyEnrollFinishRequest struct {
	EnrollmentID string `json:"enrollment_id"`
	Code         string `json:"code"`
	Signature    string `json:"signature"`
	SecondFactor string `json:"code_2fa"`
}

type DeviceKeyLoginBeginRequest struct {
	DeviceKeyID string `json:"device_key_id"`
}

type DeviceKeyLoginFinishRequest struct {
	ChallengeID string `json:"challenge_id"`
	Signature   string `json:"signature"`
}

type IdentifierRequest struct {
	Identifier string `json:"identifier"`
}

type IdentifierPasswordRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

type PasswordResetConfirmRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type RegisterRequest struct {
	Identifier         string `json:"identifier"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	AccountInviteToken string `json:"account_invite_token"`
}

type AvailabilityQuery struct {
	Username    string `query:"username"`
	Email       string `query:"email"`
	PhoneNumber string `query:"phone_number"`
}

type PasswordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type UsernameRequest struct {
	Username string `json:"username"`
}

type PreferredLanguageRequest struct {
	PreferredLanguage string `json:"preferred_language"`
}

// PasswordRequest carries a password that re-authenticates the session.
type PasswordRequest struct {
	Password string `json:"password"`
}

type LabelRequest struct {
	Label string `json:"label"`
}

type TwoFactorStepUpRequest struct {
	Code       string `json:"code"`
	Method     string `json:"method"`
	FactorID   string `json:"factor_id"`
	BackupCode bool   `json:"backup_code"`
}

type ReturnToRequest struct {
	ReturnTo string `json:"return_to"`
}

type TwoFactorEnrollRequest struct {
	Method      string  `json:"method"`
	Code        string  `json:"code"`
	PhoneNumber *string `json:"phone_number"`
	Default     bool    `json:"default"`
	FactorID    string  `json:"factor_id"`
}

type TwoFactorFactorQuery struct {
	FactorID string `query:"factor_id"`
}

type TwoFactorVerifyRequest struct {
	UserID     string `json:"user_id"`
	Code       string `json:"code"`
	Challenge  string `json:"challenge"`
	FactorID   string `json:"factor_id"`
	BackupCode bool   `json:"backup_code"`
}

type TwoFactorChallengeRequest struct {
	UserID    string `json:"user_id"`
	Challenge string `json:"challenge"`
	FactorID  string `json:"factor_id"`
}

type SolanaChallengeRequest struct {
	Address  string `json:"address"`
	Username string `json:"username"`
}

// SolanaSignInRequest is the wallet-standard sign-in output: the one
// camelCase body on the wire.
type SolanaSignInRequest struct {
	Output SolanaSignInOutput `json:"output"`
}

type SolanaSignInOutput struct {
	Account       SolanaAccount `json:"account"`
	Signature     string        `json:"signature"`
	SignedMessage string        `json:"signedMessage"`
}

type SolanaAccount struct {
	Address   string `json:"address"`
	PublicKey string `json:"publicKey"`
}

type UserListQuery struct {
	PageQuery
	Search      string `query:"search"`
	RootRole    string `query:"root_role"`
	Status      string `query:"status"`
	Sort        string `query:"sort"`
	Order       string `query:"order"`
	Entitlement string `query:"entitlement"`
}

type BanRequest struct {
	Reason string `json:"reason"`
	// Until is an RFC 3339 time or "infinite".
	Until        *string `json:"until"`
	KeepExisting bool    `json:"keep_existing"`
}

type DelegatedTokenRequest struct {
	// TTLSeconds is an optional override, clamped into the configured
	// floor/ceiling; absent or <= 0 mints the configured default.
	TTLSeconds int `json:"ttl_seconds"`
	// Audiences is an optional narrowing; every requested audience must be in
	// the configured allowlist. Absent mints the full configured list.
	Audiences []string `json:"audiences"`
	// DelegateCertificateDERB64URL is the delegate's public X.509 leaf as
	// unpadded base64url DER; the token is bound to exactly this certificate.
	// Omitted when a DPoP proof binds the token instead.
	DelegateCertificateDERB64URL string `json:"delegate_certificate_der_b64url"`
	// RequestedGrant is one host-schema JSON object passed to the authorizer
	// verbatim and never copied into the token.
	RequestedGrant json.RawMessage `json:"requested_grant"`
}

type MemberListQuery struct {
	PageQuery
	Kind []string `query:"kind"`
	Role []string `query:"role"`
}

type MemberAddRequest struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
}

type APIKeyCreateRequest struct {
	Name      string     `json:"name"`
	Role      string     `json:"role"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type InvitationCreateRequest struct {
	Role      string     `json:"role"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type InviteRedeemRequest struct {
	Code string `json:"code"`
}

type GroupQuery struct {
	GroupID string `query:"group_id"`
}

type OIDCLoginRequest struct {
	ReturnTo           string `json:"return_to"`
	AccountInviteToken string `json:"account_invite_token"`
	UI                 string `json:"ui"`
	PopupNonce         string `json:"popup_nonce"`
}

type OIDCLoginQuery struct {
	UI         string `query:"ui"`
	PopupNonce string `query:"popup_nonce"`
	ReturnTo   string `query:"return_to"`
}

type OIDCCallbackQuery struct {
	State  string `query:"state"`
	Code   string `query:"code"`
	Error  string `query:"error"`
	Format string `query:"format"`
}

// WebAuthnCredential is a browser's WebAuthn credential response, passed
// through as the browser produced it.
type WebAuthnCredential = json.RawMessage

// Responses.

// Capabilities is the public, static feature discovery.
type Capabilities struct {
	Registration           RegistrationCapabilities `json:"registration"`
	ExternalLoginProviders []ExternalLoginProvider  `json:"external_login_providers"`
	Username               UsernameCapabilities     `json:"username"`
	Password               PasswordCapabilities     `json:"password"`
	Passwordless           PasswordlessCapabilities `json:"passwordless"`
	Passkeys               PasskeyCapabilities      `json:"passkeys"`
	Solana                 SolanaCapabilities       `json:"solana"`
	Verification           VerificationCapabilities `json:"verification"`
	Channels               ChannelCapabilities      `json:"channels"`
	Languages              []string                 `json:"languages"`
	Paths                  MountPaths               `json:"paths"`
}

// MountPaths are the serving mount's anchors as full paths, so a client that
// knows one AuthKit URL finds the rest; null when not mounted.
type MountPaths struct {
	API  string  `json:"api"`
	OIDC *string `json:"oidc"`
	JWKS *string `json:"jwks"`
}

type RegistrationCapabilities struct {
	Mode                string `json:"mode"`
	InviteTokenRequired bool   `json:"invite_token_required"`
}

type ExternalLoginProvider struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	SupportsLogin        bool   `json:"supports_login"`
	SupportsRegistration bool   `json:"supports_registration"`
	SupportsLink         bool   `json:"supports_link"`
}

// UsernameCapabilities is the interactive username rule. Pattern is the fixed
// character rule; length is bounded separately. Renames says whether users
// may rename themselves, and how often.
type UsernameCapabilities struct {
	MinLength             int               `json:"min_length"`
	MaxLength             int               `json:"max_length"`
	Pattern               string            `json:"pattern"`
	Renames               bool              `json:"renames"`
	RenameIntervalSeconds int64             `json:"rename_interval_seconds"`
	FormerNames           naming.PolicyInfo `json:"former_names"`
}

// ChannelCapabilities says which contact channels can deliver now: a sender
// is configured and, for SMS, its latest health check passed.
type ChannelCapabilities struct {
	Email bool `json:"email"`
	SMS   bool `json:"sms"`
}

// PasswordCapabilities is everything a browser needs to pre-validate a new
// password except the blocklist itself. AllowCommon says the blocklist is off.
type PasswordCapabilities struct {
	MinLength        int  `json:"min_length"`
	MaxLength        int  `json:"max_length"`
	RequireUppercase bool `json:"require_uppercase"`
	RequireLowercase bool `json:"require_lowercase"`
	RequireDigit     bool `json:"require_digit"`
	RequireSymbol    bool `json:"require_symbol"`
	AllowCommon      bool `json:"allow_common"`
}

type PasswordlessCapabilities struct {
	Enabled  bool     `json:"enabled"`
	Channels []string `json:"channels"`
}

type PasskeyCapabilities struct {
	Login bool `json:"login"`
}

type SolanaCapabilities struct {
	Login bool `json:"login"`
}

type VerificationCapabilities struct {
	Registration string `json:"registration"`
}

// RegistrationNextAction says what completes a registration.
type RegistrationNextAction string

const (
	RegistrationNextActionNone        RegistrationNextAction = "none"
	RegistrationNextActionVerifyEmail RegistrationNextAction = "verify_email"
	RegistrationNextActionVerifyPhone RegistrationNextAction = "verify_phone"
)

// RegistrationResult is what happens next, who registered, and, when no
// verification is pending, the session.
type RegistrationResult struct {
	NextAction RegistrationNextAction `json:"next_action"`
	User       RegistrationUser       `json:"user"`
	TokenSet   *iam.TokenSet          `json:"token_set"`
}

type RegistrationUser struct {
	Username    string  `json:"username"`
	Email       *string `json:"email"`
	PhoneNumber *string `json:"phone_number"`
}

// Availability answers each field asked for; null for a field not asked.
type Availability struct {
	Username    *AvailabilityField `json:"username"`
	Email       *AvailabilityField `json:"email"`
	PhoneNumber *AvailabilityField `json:"phone_number"`
}

// AvailabilityField is one answer; Error is the wire code that makes the
// value unavailable.
type AvailabilityField struct {
	Available bool    `json:"available"`
	Error     *string `json:"error"`
}

// PasswordlessResult is a passwordless sign-in's session.
type PasswordlessResult struct {
	TokenSet iam.TokenSet `json:"token_set"`
	ReturnTo *string      `json:"return_to"`
}

// DeviceKeyEnrollment is an enrollment ceremony in progress: the challenge
// to sign, beside the code emailed to the address.
type DeviceKeyEnrollment struct {
	EnrollmentID string    `json:"enrollment_id"`
	Challenge    string    `json:"challenge"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// DeviceKeyLoginChallenge is the challenge a device key signs to sign in.
type DeviceKeyLoginChallenge struct {
	ChallengeID string    `json:"challenge_id"`
	Challenge   string    `json:"challenge"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// DeviceKeySession is a device key's sign-in; the key is the token's own.
type DeviceKeySession struct {
	TokenSet  iam.TokenSet  `json:"token_set"`
	DeviceKey iam.DeviceKey `json:"device_key"`
}

// FreshAuth is the session's step-up state after a re-authentication.
type FreshAuth struct {
	StepUpRequiredForSensitiveActions bool       `json:"step_up_required_for_sensitive_actions"`
	TimeUntilStepUpRequired           int64      `json:"time_until_step_up_required"`
	LastAuthenticatedAt               *time.Time `json:"last_authenticated_at"`
	AuthMethods                       []string   `json:"auth_methods"`
}

// StepUpResult is a re-authenticated session: a fresh access token whose
// assurance claims match the session.
type StepUpResult struct {
	TokenSet  iam.TokenSet `json:"token_set"`
	FreshAuth FreshAuth    `json:"fresh_auth"`
}

// OIDCStepUpResult is StepUpResult from a provider callback asked for JSON.
type OIDCStepUpResult struct {
	TokenSet  iam.TokenSet `json:"token_set"`
	FreshAuth FreshAuth    `json:"fresh_auth"`
	Provider  string       `json:"provider"`
}

// OIDCStart is where to send the browser to sign in with a provider.
type OIDCStart struct {
	AuthURL string `json:"auth_url"`
	State   string `json:"state"`
}

// OIDCLoginResult is a provider sign-in's session, for a callback asked for
// JSON.
type OIDCLoginResult struct {
	TokenSet iam.TokenSet `json:"token_set"`
	User     OIDCUser     `json:"user"`
}

type OIDCUser struct {
	ID    string  `json:"id"`
	Email *string `json:"email"`
}

type UsernameChange struct {
	Username string       `json:"username"`
	Naming   naming.State `json:"naming"`
}

type PreferredLanguage struct {
	PreferredLanguage string `json:"preferred_language"`
}

type TwoFactorStatus struct {
	Enabled              bool              `json:"enabled"`
	Method               string            `json:"method"`
	PhoneNumber          *string           `json:"phone_number"`
	DefaultFactor        *TwoFactorFactor  `json:"default_factor"`
	Factors              []TwoFactorFactor `json:"factors"`
	AllowedMethods       []string          `json:"allowed_methods"`
	BackupCodesRemaining int               `json:"backup_codes_remaining"`
}

type TwoFactorFactor struct {
	ID          string  `json:"id"`
	Method      string  `json:"method"`
	IsDefault   bool    `json:"is_default"`
	PhoneNumber *string `json:"phone_number"`
	// Email is the masked address an email factor's codes go to.
	Email *string `json:"email"`
}

// TwoFactorEnrollResult is a TOTP enrollment started (Secret, OTPAuthURI) or
// a factor enabled (Enabled, BackupCodes on the first factor; TokenSet when
// the enrollment signed the caller in or re-verified the session, with
// FreshAuth for the latter).
type TwoFactorEnrollResult struct {
	Method      string        `json:"method"`
	Enabled     bool          `json:"enabled"`
	Secret      *string       `json:"secret"`
	OTPAuthURI  *string       `json:"otpauth_uri"`
	BackupCodes []string      `json:"backup_codes"`
	TokenSet    *iam.TokenSet `json:"token_set"`
	FreshAuth   *FreshAuth    `json:"fresh_auth"`
}

// RemovedRoles are the roles disabling a factor removed, because they need
// MFA the account no longer has.
type RemovedRoles struct {
	RemovedRoles []RemovedRole `json:"removed_roles"`
}

type RemovedRole struct {
	GroupID   string      `json:"group_id"`
	Persona   iam.Persona `json:"persona"`
	Role      iam.Role    `json:"role"`
	RemovedAt time.Time   `json:"removed_at"`
}

type BackupCodes struct {
	BackupCodes []string `json:"backup_codes"`
}

type SolanaChallenge struct {
	Nonce    string    `json:"nonce"`
	IssuedAt time.Time `json:"issued_at"`
	// Message is the Sign-In-With-Solana text the wallet signs.
	Message string `json:"message"`
}

type SolanaLoginResult struct {
	TokenSet iam.TokenSet `json:"token_set"`
	Created  bool         `json:"created"`
	User     SolanaUser   `json:"user"`
}

type SolanaUser struct {
	ID            string `json:"id"`
	SolanaAddress string `json:"solana_address"`
}

type SolanaLink struct {
	SolanaAddress string `json:"solana_address"`
}

// RoleInfo is one role of a group's persona and the permissions it grants.
type RoleInfo struct {
	Name        iam.Role `json:"name"`
	Permissions []string `json:"permissions"`
}

// PermissionSet is the caller's effective grants in one group.
type PermissionSet struct {
	GroupID     string     `json:"group_id"`
	Permissions []iam.Perm `json:"permissions"`
}

// UserProfile is GET /me: the account and its sign-in, security and naming
// state.
type UserProfile = authflow.UserProfile
