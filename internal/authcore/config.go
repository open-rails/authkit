package authcore

import (
	"time"

	"github.com/open-rails/authkit/authprovider"
	jwtkit "github.com/open-rails/authkit/jwt"
	oidckit "github.com/open-rails/authkit/oidc"
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
	// RBAC declares the app permission catalog, default roles, and owner policy.
	RBAC RBACConfig

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
	// resolution turns on automatically when a resolver is supplied via the
	// WithSolanaSNSResolver option; its lookup timeout (3s) and cache TTL (24h)
	// are fixed constants, not configurable.
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
	// CallbackPath is the host-owned frontend route that receives full-page OIDC
	// login results. Empty defaults to "/login/callback". (Paths for
	// reset/verify are fixed to "/reset"/"/verify" — not configurable.)
	CallbackPath string
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

// SolanaConfig controls SIWS chain selection and optional SNS resolution.
type SolanaConfig struct {
	// Network is a host-provided chain selector ("mainnet"/"testnet"/"devnet").
	// If empty, AuthKit derives a default from Environment.
	Network string
	// SNSEnabled enables AuthKit-owned Solana Name Service resolution for
	// SIWS-linked wallets.
	SNSEnabled bool
	// SNSResolver resolves a verified Solana wallet address to its primary .sol name.
	SNSResolver SolanaSNSResolver
	// SNSLookupTimeout bounds resolver calls. Empty defaults to 3 seconds.
	SNSLookupTimeout time.Duration
	// SNSCacheTTL controls when cached SNS metadata is stale. Empty defaults to 24h.
	SNSCacheTTL time.Duration
}

// IdentityConfig declares external OAuth2/OIDC identity providers.
type IdentityConfig struct {
	// Providers – identity providers by name ("google"/"apple"/"github"/
	// "discord"). Only client id/secret are required; standard scopes derive
	// from defaults.
	Providers map[string]oidckit.RPConfig
	// ProviderDescriptors define OAuth2/OIDC providers using config-first
	// descriptors. They augment/override built-in Providers entries and are the
	// preferred path for adding custom providers.
	ProviderDescriptors map[string]authprovider.Provider
}

// APIKeysConfig configures opaque permission-group-owned machine credentials.
type APIKeysConfig struct {
	// Prefix is the issuing application's brand prefix for generated API keys
	// (single value per deployment). Empty defaults to the bare `st_` marker.
	// Must be lowercase alphanumeric, 1-16 chars.
	Prefix string
	// MaxTTL caps how far in the future a minted API key may expire. 0 (default)
	// means no cap (keys may be non-expiring); when set, a requested expiry
	// beyond now+MaxTTL (incl. no-expiry) is capped at mint time. The resource-
	// scope authorizer is injected via the WithResourceScopeAuthorizer option.
	MaxTTL time.Duration
}

// TwoFactorConfig configures optional 2FA methods.
type TwoFactorConfig struct {
	// TOTPSecretKey encrypts persisted authenticator-app shared secrets. It must
	// be 16, 24, or 32 bytes. Without it, TOTP enrollment fails closed.
	TOTPSecretKey []byte
}

// PasskeyConfig configures WebAuthn relying-party identity and UV policy.
type PasskeyConfig struct {
	RPID             string
	RPDisplayName    string
	Origins          []string
	UserVerification string
}

// RBACConfig declares the app permission catalog, default roles, and owner policy.
type RBACConfig struct {
	// Permissions is the embedding application's set of valid permission strings
	// (e.g. `endpoint:revise`, `repo:create`); authkit stores and validates them
	// as opaque catalog entries. The permission-group personas declared in Groups
	// (#111) are the current model for scoping permissions.
	Permissions []PermissionDef

	// Groups declares the app's permission-group personas (#111): the containment
	// schema + per-type role catalogs + management profiles. authkit injects the
	// intrinsic `root` type when absent, so an empty slice yields a valid
	// root-only deployment. Validated by NewFromConfig via BuildSchema.
	Groups []PersonaDef
}

// PermissionDef is one entry in the permission set: an opaque permission
// string plus a human-readable description (surfaced to admin UIs).
type PermissionDef struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type RegistrationVerificationPolicy string

const (
	RegistrationVerificationNone     RegistrationVerificationPolicy = "none"
	RegistrationVerificationOptional RegistrationVerificationPolicy = "optional"
	RegistrationVerificationRequired RegistrationVerificationPolicy = "required"
)

type RegistrationMode string

const (
	RegistrationModeOpen               RegistrationMode = "open"
	RegistrationModeInviteOnly         RegistrationMode = "invite_only"
	RegistrationModeAdminOnly          RegistrationMode = "admin_only"
	RegistrationModeAdminBootstrapOnly RegistrationMode = "admin_bootstrap_only"
	RegistrationModeManifestOnly       RegistrationMode = "manifest_only"
	RegistrationModeClosed             RegistrationMode = "closed"
)
