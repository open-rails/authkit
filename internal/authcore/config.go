package authcore

import (
	"time"

	"github.com/open-rails/authkit/authprovider"
	jwtkit "github.com/open-rails/authkit/jwt"
)

// Config is the host-provided configuration for an AuthKit Service. Fields are
// grouped by concern into typed sub-structs (#108). It carries DATA/POLICY only;
// runtime dependencies (Postgres, Redis, senders, loggers) are injected via the
// constructor's functional options, not here.
type Config struct {
	// Token is the JWT issuing/verification contract and session limits.
	Token TokenConfig
	// Frontend describes host-owned frontend routes used for absolute-URL and
	// full-page OIDC callback construction.
	Frontend FrontendConfig
	// Registration controls verification policy and public self-registration.
	Registration RegistrationConfig
	// Keys controls signing-key resolution (or verify-only mode).
	Keys KeysConfig
	// Identity declares external OAuth2/OIDC identity providers.
	Identity IdentityConfig
	// APIKeys configures opaque permission-group-owned machine credentials.
	APIKeys APIKeysConfig
	// TwoFactor configures optional MFA features.
	TwoFactor TwoFactorConfig
	// Passkeys configures WebAuthn/FIDO2 passkey ceremonies.
	Passkeys PasskeyConfig
	// RBAC declares the app's permission-group personas (#111): containment
	// schema plus per-persona role catalogs. Empty yields root-only.
	RBAC []PersonaDef

	// Environment is a host-provided runtime mode string used for dev/prod
	// behavior checks. "prod"/"production" mean production; anything else is
	// treated as non-prod.
	Environment string

	// Schema is the Postgres schema AuthKit's tables live in. Empty defaults to
	// "profiles" (the historical hard-coded name). Set it when multiple apps
	// embed AuthKit against the same database and must not share auth tables
	// (authkit issue 69). The name must match ^[a-z_][a-z0-9_]*$ (max 63 bytes);
	// NewFromConfig rejects anything else. Hosts that set a non-default schema
	// must also run the migrations rendered for that schema — see
	// migrations/postgres.FSForSchema.
	Schema string

	// SolanaNetwork is the SIWS chain selector ("mainnet"/"testnet"/"devnet").
	// Empty derives a default from Environment. Solana Name Service (SNS)
	// resolution is AuthKit-owned: it uses the built-in keyless resolver, with a
	// fixed 3s lookup timeout and 24h cache TTL. There is no host override.
	SolanaNetwork string
}

// TokenConfig is the JWT issuing/verification contract plus session limits.
type TokenConfig struct {
	Issuer               string
	IssuedAudiences      []string // tokens issued will contain ALL of these audiences
	ExpectedAudiences    []string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	// SessionMaxPerUser caps concurrent refresh sessions per user. 0 = unlimited
	// (default 3 if unset by the service); eviction is always evict-oldest.
	SessionMaxPerUser int
}

// FrontendConfig describes host-owned frontend routes.
type FrontendConfig struct {
	// BaseURL, if set, is used for building absolute URLs (e.g. password
	// reset/verify links). If empty and Token.Issuer is a well-formed URL,
	// NewFromConfig defaults it to the issuer.
	BaseURL string
	// OIDCReturnPath is the host SPA landing route AuthKit redirects to after it
	// finishes an OIDC/social login flow (the browser is sent to
	// BaseURL + OIDCReturnPath with the login result). This is NOT the backend
	// OAuth/OIDC provider callback URL — AuthKit owns that. Empty defaults to
	// "/login/callback".
	OIDCReturnPath string
	// VerifyPath is the host-owned frontend route that receives scanner-safe
	// verification link landings. Empty defaults to "/verify".
	VerifyPath string
	// PasswordResetPath is the host-owned frontend route that receives
	// scanner-safe password reset link landings. Empty defaults to "/reset".
	PasswordResetPath string
	// PasswordlessPath is the host-owned frontend route that receives
	// passwordless login magic links. Empty defaults to "/passwordless".
	PasswordlessPath string
	// InvitePath is the host-owned frontend route that receives permission-group
	// invite links (`?code=…`); the SPA reads the code and POSTs it to the redeem
	// endpoint. Empty defaults to "/accept-invite". (#134)
	InvitePath string
}

// RegistrationConfig controls verification policy and public self-registration.
type RegistrationConfig struct {
	// Verification controls registration verification: "none"|"optional"|
	// "required". Empty defaults to "none".
	Verification RegistrationVerificationPolicy
	// NativeUserMode controls public native-user self-registration. Empty
	// defaults to "open". Non-open modes disable every public user-creation path
	// while leaving embedded admin/bootstrap core APIs available.
	NativeUserMode RegistrationMode
	// PasswordlessLogin enables contact-based passwordless sessions. Off by
	// default; hosts must opt in before /passwordless/start sends challenges.
	PasswordlessLogin bool
	// PasswordlessAutoRegistration lets a verified unknown contact create a
	// no-password user during passwordless confirmation. Off by default.
	PasswordlessAutoRegistration bool
}

// KeysConfig controls signing-key resolution.
type KeysConfig struct {
	// Source can be nil — if nil, authkit auto-discovers keys: (1) env vars
	// (ACTIVE_KEY_ID, ACTIVE_PRIVATE_KEY_PEM, PUBLIC_KEYS); (2) filesystem
	// <Path>/keys.json (default /vault/auth); (3) auto-generated keys in
	// .runtime/authkit/ (dev fallback; prod hard-fail). Hosts NEVER handle the
	// private key — they delegate the signing OPERATION to authkit; there is no
	// API that returns a private key or PEM (a future Vault-Transit backend,
	// authkit future #72, drops in behind the same Signer seam).
	Source jwtkit.KeySource
	// Path overrides the filesystem DIRECTORY the local key resolver scans for
	// keys.json when Source is nil. Empty defaults to AUTHKIT_KEYS_PATH, then
	// /vault/auth.
	Path string
	// VerifyOnly constructs the Service with NO active signer (#87): token
	// MINTING returns ErrMissingSigner, while VERIFICATION and all RBAC reads
	// work fully and the JWKS endpoint serves an empty key set. When true, key
	// auto-discovery is SKIPPED. Ignored when Source is non-nil. Use it for a
	// pure resource-server / control-plane deployment that only verifies inbound
	// tokens.
	VerifyOnly bool
}

// IdentityConfig declares external OAuth2/OIDC identity providers.
type IdentityConfig struct {
	// Providers is the list of external identity providers — a provider is a
	// provider, there is no built-in-vs-custom split (#143). Use a built-in
	// constructor for the common ones (authprovider.Google/Apple/Discord/GitHub,
	// which need only client id/secret and derive standard scopes/mapping) or a
	// full authprovider.Provider descriptor for any other OAuth2/OIDC provider.
	// Each provider carries its own Name.
	Providers []authprovider.Provider
}

// APIKeysConfig configures opaque permission-group-owned machine credentials.
type APIKeysConfig struct {
	// Prefix is the issuing application's brand prefix for generated API keys
	// (single value per deployment). Empty defaults to the bare `st_` marker.
	// Must be lowercase alphanumeric, 1-16 chars.
	Prefix string
	// MaxTTL caps how far in the future a minted API key may expire. 0 (default)
	// means no cap (keys may be non-expiring); when set, a requested expiry
	// beyond now+MaxTTL (incl. no-expiry) is capped at mint time.
	MaxTTL time.Duration
}

// TwoFactorConfig configures 2FA policy and key material (#148).
type TwoFactorConfig struct {
	// Mode is the account-wide 2FA policy: Disabled (no enroll/challenge/verify
	// routes usable), Optional (users may enroll), or Required (every user must
	// enroll before normal session use; existing un-enrolled users are challenged
	// on their next authenticated request). Empty defaults to Optional. Per-role
	// RoleDef.RequiresMFA remains available for narrower enforcement.
	Mode TwoFactorMode

	// Methods is the set of second-factor channels the host enables
	// (Email/SMS/TOTP). Empty defaults to all three. A method whose dependency is
	// missing (e.g. SMS with no SMS sender) fails closed regardless of this list.
	Methods []TwoFactorMethod

	// TOTPSecretKey encrypts persisted authenticator-app shared secrets. It must
	// be 16, 24, or 32 bytes. This is an OVERRIDE for tests/custom key management;
	// the normal path loads the key from <Keys.Path>/totp.key (vault-mounted key
	// material, same model as JWT signing keys). Without either, TOTP enrollment
	// fails closed.
	TOTPSecretKey []byte
}

// PasskeyConfig configures WebAuthn relying-party identity and UV policy.
type PasskeyConfig struct {
	RPID             string
	RPDisplayName    string
	Origins          []string
	UserVerification string
}

// RegistrationVerificationPolicy and RegistrationMode are defined in authkit and
// re-exported in registration.go (#147).
