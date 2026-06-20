package core

import (
	"time"

	"github.com/open-rails/authkit/authprovider"
	jwtkit "github.com/open-rails/authkit/jwt"
	oidckit "github.com/open-rails/authkit/oidc"
)

// Config mirrors the simplicity of go-pkgz/auth: provide issuer, durations, and keys.
type Config struct {
	Issuer               string
	IssuedAudiences      []string // JWT audiences - tokens issued will contain ALL of these audiences
	ExpectedAudiences    []string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	// Session limits
	SessionMaxPerUser int // 0 = unlimited, default 3 if unset by service; eviction is always evict-oldest
	// Optional: if set, used for building absolute URLs (e.g., password reset/verify links).
	// If empty and Issuer is a well-formed URL, NewFromConfig defaults BaseURL to Issuer.
	BaseURL string
	// FrontendCallbackPath is the host-owned frontend route that receives full-page
	// OIDC login results. Empty defaults to "/login/callback".
	FrontendCallbackPath string

	// Schema is the Postgres schema AuthKit's tables live in. Empty defaults to
	// "profiles" (the historical hard-coded name), which is fully
	// backward-compatible. Set it when multiple apps embed AuthKit against the
	// same database and must not share auth tables (authkit issue 69). The name
	// must match ^[a-z_][a-z0-9_]*$ (max 63 bytes); NewFromConfig rejects
	// anything else. Hosts that set a non-default schema must also run the
	// migrations rendered for that schema — see migrations/postgres.FSForSchema.
	Schema string
	// Paths for reset/verify are fixed to "/reset" and "/verify"; not configurable.

	// RegistrationVerification controls registration verification behavior.
	// Valid values: "none", "optional", "required".
	// Empty defaults to "none".
	RegistrationVerification RegistrationVerificationPolicy

	// AutoCreatePersonalOrgs creates a personal org for each native user at
	// signup. Direct host opt-in (authkit issue 60): orgs are always a supported
	// primitive, so this is no longer gated on a global org mode. Empty/false
	// means native users can exist without org rows; hosts that want
	// personal/team workspaces opt in.
	AutoCreatePersonalOrgs bool

	// NativeUserRegistrationMode controls public native-user self-registration.
	// Empty defaults to "open". Non-open modes disable every public user
	// creation path while leaving embedded admin/bootstrap core APIs available.
	NativeUserRegistrationMode RegistrationMode

	// OrgRegistrationMode controls public org onboarding/management.
	// Empty defaults to "open". Non-open modes disable public org mutation
	// routes while leaving manifest/admin/bootstrap core APIs available.
	OrgRegistrationMode RegistrationMode

	// Environment is a host-provided runtime mode string used for dev/prod behavior checks.
	// Expected values include "prod"/"production" for production, anything else is treated as non-prod.
	Environment string

	// SolanaNetwork is a host-provided Solana chain selector ("mainnet", "testnet", "devnet").
	// If empty, AuthKit derives a default from Environment.
	SolanaNetwork string
	// SolanaSNSEnabled enables AuthKit-owned Solana Name Service resolution for SIWS-linked wallets.
	SolanaSNSEnabled bool
	// SolanaSNSResolver resolves a verified Solana wallet address to its primary .sol name.
	SolanaSNSResolver SolanaSNSResolver
	// SolanaSNSLookupTimeout bounds resolver calls. Empty defaults to 3 seconds.
	SolanaSNSLookupTimeout time.Duration
	// SolanaSNSCacheTTL controls when cached SNS metadata is considered stale. Empty defaults to 24 hours.
	SolanaSNSCacheTTL time.Duration

	// Keys can be nil - if nil, authkit auto-discovers keys with this priority:
	// 1. Environment variables (ACTIVE_KEY_ID, ACTIVE_PRIVATE_KEY_PEM, PUBLIC_KEYS)
	// 2. Filesystem <KeysPath>/keys.json (default /vault/auth; External Secrets
	//    Operator in K8s). Override the directory with KeysPath or the
	//    AUTHKIT_KEYS_PATH env var.
	// 3. Auto-generated keys in .runtime/authkit/ (development fallback; prod hard-fail)
	//
	// Hosts NEVER handle the private key: they delegate the signing OPERATION to
	// authkit (the Service mint methods / the internal Signer). There is no API
	// that returns a private key or PEM. A future remote Vault-Transit backend
	// (authkit future #72) drops in behind the same Signer seam with no host
	// changes.
	Keys jwtkit.KeySource

	// VerifyOnly constructs the Service with NO active signer (#87): token
	// MINTING (IssueAccessToken, MintServiceJWT/MintCustomJWT/
	// MintDelegatedAccessToken, remote_application self-tokens) returns
	// ErrMissingSigner, while VERIFICATION and all RBAC reads work fully and the
	// JWKS endpoint serves an empty key set. When true, key auto-discovery is
	// SKIPPED — no env/file/dev key is required to boot. Ignored when Keys is
	// non-nil (an explicit KeySource wins). Use it for a pure resource-server /
	// control-plane deployment that only verifies inbound tokens (e.g. OpenRails
	// standalone with no login-capable users).
	VerifyOnly bool

	// KeysPath overrides the filesystem DIRECTORY the local key resolver scans
	// for keys.json when Keys is nil. Empty defaults to the AUTHKIT_KEYS_PATH
	// env var, then to /vault/auth, so existing embedders are unchanged. Use it
	// when the host renders its keyset outside K8s (e.g. a host-run dev mount).
	KeysPath string

	// Providers – identity providers by name ("google", "apple", "github", "discord").
	// Only client id/secret are required; standard scopes are derived from defaults.
	Providers map[string]oidckit.RPConfig

	// ProviderDescriptors define OAuth2/OIDC providers using config-first
	// descriptors. These augment/override built-in Providers entries and are
	// the preferred path for adding custom providers.
	ProviderDescriptors map[string]authprovider.Provider

	// APIKeyPrefix is the issuing application's brand prefix for generated API
	// keys. It is a single value per deployment (NOT per-org) and a free brand
	// choice by the host app. Empty defaults to the legacy bare `st_` marker.
	// Must be lowercase alphanumeric, 1-16 chars. A unique app prefix lets leak
	// scanners and push-protection partners identify the issuer at a glance.
	APIKeyPrefix string

	// APIKeyMaxTTL caps how far in the future a minted API key may expire.
	// 0 (default) means no cap (keys may be non-expiring). When set, a
	// requested expiry beyond now+MaxTTL — including a null/no-expiry request —
	// is capped to now+MaxTTL at mint time.
	APIKeyMaxTTL time.Duration

	// ResourceScopeAuthorizer optionally authorizes host-defined API-key resource
	// scopes during HTTP minting. AuthKit validates only shape/length and stores
	// resource Kind/ID pairs opaquely; the embedding host owns semantic
	// no-escalation such as "may this caller mint openrails.customer=cozy-art".
	ResourceScopeAuthorizer ResourceScopeAuthorizer

	// PermissionCatalog is the embedding application's set of valid permission
	// strings (e.g. tensorhub's `endpoint:revise`, `repo:create`). authkit merges
	// this with its own base permissions (the reserved `org:` namespace) to form
	// the catalog it validates role/API-key grants against. Permissions are opaque to
	// authkit — it never interprets their meaning. Names must not collide with
	// the reserved `org:` base permissions.
	PermissionCatalog []PermissionDef

	// DefaultRoles are role templates seeded into every org at creation, in
	// addition to the built-in `owner` role (which is always seeded with
	// `org:*`). Permission tokens are concrete perms (`org:members:read`) or
	// namespace-anchored globs (`org:*`, `org:members:*`, `org:*:read`). There
	// is NO bare `*` and NO `!perm` negation — positive grants only (#93/#95).
	// e.g. a least-privilege `admin` = {"org:members:*", "org:roles:read"}.
	DefaultRoles []DefaultRole
}

// PermissionDef is one entry in the permission catalog: an opaque permission
// string plus a human-readable description (surfaced to admin UIs).
type PermissionDef struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// DefaultRole is a role template seeded into every org at creation: a role name
// and its permission set (tokens are concrete perms or namespace-anchored globs
// like `org:*`/`org:*:read`; no bare `*`, no `!perm` negation).
type DefaultRole struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
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
