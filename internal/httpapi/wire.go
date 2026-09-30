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
	Limit  *int   `query:"limit"`
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
	Identifier        string `json:"identifier"`
	Mode              string `json:"mode"`
	ReturnTo          string `json:"return_to"`
	PreferredLanguage string `json:"preferred_language"`
	InviteCode        string `json:"invite_code"`
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
	Identifier string `json:"identifier"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	InviteCode string `json:"invite_code"`
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
	BackupCode bool   `json:"backup_code"`
}

// TwoFactorSendRequest names the second factor a step-up code goes to (the
// default when empty).
type TwoFactorSendRequest struct {
	Method string `json:"method"`
}

// ProfileUpdateRequest is PATCH /me: an absent field is unchanged; an empty
// avatar_url clears it.
type ProfileUpdateRequest struct {
	Username          *string `json:"username"`
	PreferredLanguage *string `json:"preferred_language"`
	AvatarURL         *string `json:"avatar_url"`
}

type EmailChangeRequest struct {
	Email string `json:"email"`
}

type PhoneChangeRequest struct {
	PhoneNumber string `json:"phone_number"`
}

// TwoFactorSetupRequest starts a factor's setup: a code to the email or phone,
// or an authenticator app's secret.
type TwoFactorSetupRequest struct {
	Method      string  `json:"method"`
	PhoneNumber *string `json:"phone_number"`
}

// TwoFactorFactorCreateRequest adds the factor whose setup code it carries.
type TwoFactorFactorCreateRequest struct {
	Method      string  `json:"method"`
	Code        string  `json:"code"`
	PhoneNumber *string `json:"phone_number"`
	Default     bool    `json:"default"`
}

type TwoFactorFactorUpdateRequest struct {
	Default bool `json:"default"`
}

// SessionEventQuery pages a session history, newest first; kind repeats.
type SessionEventQuery struct {
	PageQuery
	Kind []string `query:"kind"`
}

// UsersQuery looks public users up by id (comma-separated, at most 100) or
// by username (former names resolve too).
type UsersQuery struct {
	IDs      string `query:"ids"`
	Username string `query:"username"`
}

type ReturnToRequest struct {
	ReturnTo string `json:"return_to"`
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

// UserListQuery is the admin user directory's query. total=true counts every
// match into the page's total, at the price of a count.
type UserListQuery struct {
	PageQuery
	Search      string `query:"search"`
	RootRole    string `query:"root_role"`
	Status      string `query:"status"`
	Sort        string `query:"sort"`
	Order       string `query:"order"`
	Entitlement string `query:"entitlement"`
	Total       bool   `query:"total"`
}

// BanRequest is the ban to put in force; a null until bans indefinitely.
type BanRequest struct {
	Reason *string    `json:"reason"`
	Until  *time.Time `json:"until"`
}

// AdminUserUpdateRequest is PATCH /admin/users/{user_id}: an absent field is
// unchanged.
type AdminUserUpdateRequest struct {
	Email             *string `json:"email"`
	PhoneNumber       *string `json:"phone_number"`
	Username          *string `json:"username"`
	AvatarURL         *string `json:"avatar_url"`
	PreferredLanguage *string `json:"preferred_language"`
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

// MemberListQuery filters a group's members; kind and role repeat, and
// expand=user adds each user member's PublicUser.
type MemberListQuery struct {
	PageQuery
	Kind   []string `query:"kind"`
	Role   []string `query:"role"`
	Expand []string `query:"expand"`
}

// MemberRoleRequest is the role a member holds in the group.
type MemberRoleRequest struct {
	Role string `json:"role"`
}

type APIKeyCreateRequest struct {
	Name      string     `json:"name"`
	Role      string     `json:"role"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// InvitationCreateRequest makes an invite link (no email), or emails an
// invitation. A root invitation with an email and no role invites someone to
// register.
type InvitationCreateRequest struct {
	Role      string     `json:"role"`
	Email     string     `json:"email"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type InvitationRedeemRequest struct {
	Code string `json:"code"`
}

type GroupQuery struct {
	GroupID string `query:"group_id"`
}

type OIDCLoginStartRequest struct {
	ReturnTo   string `json:"return_to"`
	InviteCode string `json:"invite_code"`
	UI         string `json:"ui"`
	PopupNonce string `json:"popup_nonce"`
}

// OIDCExchangeRequest trades a browser OIDC result's one-time code.
type OIDCExchangeRequest struct {
	Code string `json:"code"`
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
	TwoFactor              TwoFactorCapabilities    `json:"two_factor"`
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
// is configured and its latest health check, if any, passed.
type ChannelCapabilities struct {
	Email bool `json:"email"`
	SMS   bool `json:"sms"`
}

// TwoFactorCapabilities is the 2FA policy and the second factors a user can
// enroll now (Client.TwoFactorMethods).
type TwoFactorCapabilities struct {
	Mode    iam.TwoFactorMode     `json:"mode"`
	Methods []iam.TwoFactorMethod `json:"methods"`
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

// AuthStatus is where a sign-in stands.
type AuthStatus string

const (
	// AuthComplete: signed in (or re-authenticated); token_set and user are set.
	AuthComplete AuthStatus = "complete"
	// AuthSecondFactorRequired: the first factor passed; answer second_factor
	// at POST /2fa/verify (or switch factor at POST /2fa/challenge).
	AuthSecondFactorRequired AuthStatus = "second_factor_required"
	// AuthEnrollmentRequired: the account must add a second factor first;
	// enrollment.token_set reaches only POST /me/2fa/setup and /me/2fa/factors.
	AuthEnrollmentRequired AuthStatus = "enrollment_required"
	// AuthVerificationRequired: a code went to verification.identifier; confirm
	// it at POST /verify/confirm.
	AuthVerificationRequired AuthStatus = "verification_required"
	// AuthAccountRecoveryRequired: the account is deleted and restorable;
	// confirm recovery.token at POST /account/recovery/confirm.
	AuthAccountRecoveryRequired AuthStatus = "account_recovery_required"
)

// AuthResult is every sign-in and re-authentication answer: a session, or
// the one next step the status names. Only the members of that status are
// set; the rest are null.
type AuthResult struct {
	Status   AuthStatus    `json:"status"`
	TokenSet *iam.TokenSet `json:"token_set"`
	User     *iam.User     `json:"user"`
	// Created: this sign-in created the account.
	Created  bool    `json:"created"`
	ReturnTo *string `json:"return_to"`
	// FreshAuth: the session's step-up state after a re-authentication.
	FreshAuth *FreshAuth `json:"fresh_auth"`
	// DeviceKey: a device-key sign-in's key.
	DeviceKey    *iam.DeviceKey                        `json:"device_key"`
	SecondFactor *SecondFactorStep                     `json:"second_factor"`
	Enrollment   *EnrollmentStep                       `json:"enrollment"`
	Verification *VerificationStep                     `json:"verification"`
	Recovery     *authflow.AccountRecoveryConfirmation `json:"recovery"`
}

// SecondFactorStep is a sign-in waiting on its second factor: the challenge
// to answer, the factor its code went to, and the factors to switch to.
type SecondFactorStep struct {
	UserID    string            `json:"user_id"`
	Challenge string            `json:"challenge"`
	Factor    TwoFactorFactor   `json:"factor"`
	Factors   []TwoFactorFactor `json:"factors"`
}

// EnrollmentStep is a sign-in waiting on a first second factor. TokenSet is
// a restricted enrollment token, not a session.
type EnrollmentStep struct {
	TokenSet       iam.TokenSet          `json:"token_set"`
	AllowedMethods []iam.TwoFactorMethod `json:"allowed_methods"`
}

// VerificationStep is a sign-in waiting on a contact proof; the code went to
// Identifier over Channel ("email" or "phone").
type VerificationStep struct {
	Identifier string `json:"identifier"`
	Channel    string `json:"channel"`
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

// FreshAuth is the session's step-up state after a re-authentication.
type FreshAuth = authflow.FreshAuth

// OIDCStart is where to send the browser to sign in with a provider.
type OIDCStart struct {
	AuthURL string `json:"auth_url"`
	State   string `json:"state"`
}

// TwoFactorStatus is the caller's second factors.
type TwoFactorStatus struct {
	Enabled              bool                  `json:"enabled"`
	Factors              []TwoFactorFactor     `json:"factors"`
	AllowedMethods       []iam.TwoFactorMethod `json:"allowed_methods"`
	BackupCodesRemaining int                   `json:"backup_codes_remaining"`
}

// TwoFactorFactor is one second factor. Destination is the masked address its
// codes go to; null for an authenticator app.
type TwoFactorFactor struct {
	ID          string  `json:"id"`
	Method      string  `json:"method"`
	IsDefault   bool    `json:"is_default"`
	Destination *string `json:"destination"`
}

// TwoFactorSetup is a factor's setup under way: where its code went, or the
// authenticator app's secret.
type TwoFactorSetup struct {
	Method      string  `json:"method"`
	Destination *string `json:"destination"`
	Secret      *string `json:"secret"`
	OTPAuthURI  *string `json:"otpauth_uri"`
}

// TwoFactorFactorCreated is a factor added. BackupCodes are the first
// factor's, shown once ([] otherwise). Auth is the sign-in an enrollment token
// finished, or the session's fresh token when the code re-verified it; null
// otherwise.
type TwoFactorFactorCreated struct {
	Factor      TwoFactorFactor `json:"factor"`
	BackupCodes []string        `json:"backup_codes"`
	Auth        *AuthResult     `json:"auth"`
}

// SignInKeyKind names a sign-in key's protocol.
type SignInKeyKind string

const (
	SignInKeyPasskey   SignInKeyKind = "passkey"
	SignInKeyDeviceKey SignInKeyKind = "device_key"
)

// SignInKey is one of the caller's passkeys or device keys. Current marks the
// device key behind the request's token.
type SignInKey struct {
	ID         string        `json:"id"`
	Kind       SignInKeyKind `json:"kind"`
	Label      *string       `json:"label"`
	CreatedAt  time.Time     `json:"created_at"`
	LastUsedAt *time.Time    `json:"last_used_at"`
	Current    bool          `json:"current"`
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

// RoleInfo is one role of a group's persona and every permission it grants,
// expanded from its patterns over the persona's catalog.
type RoleInfo struct {
	Name        iam.Role   `json:"name"`
	Permissions []iam.Perm `json:"permissions"`
}

// PermissionSet is the caller's role and effective permissions in one group,
// expanded over the persona's catalog: set membership, no pattern matching.
type PermissionSet struct {
	GroupID     string     `json:"group_id"`
	Role        *iam.Role  `json:"role"`
	Permissions []iam.Perm `json:"permissions"`
}

// UserProfile is GET /me: the account and its sign-in and naming state.
type UserProfile = authflow.UserProfile

// UserSecurity is GET /me/security: the session's freshness and the
// account's step-up and MFA state.
type UserSecurity = authflow.UserSecurity
