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
	// Paths for reset/verify are fixed to "/reset" and "/verify"; not configurable.

	// RegistrationVerification controls registration verification behavior.
	// Valid values: "none", "optional", "required".
	// Empty defaults to "none".
	RegistrationVerification RegistrationVerificationPolicy

	// TenantMode controls multi-tenant behavior.
	// Valid values: "single" (default) or "multi".
	TenantMode string

	// NativeUserRegistrationMode controls public native-user self-registration.
	// Empty defaults to "open". "bootstrap_only" disables every public user
	// creation path while leaving embedded admin/bootstrap core APIs available.
	NativeUserRegistrationMode RegistrationMode

	// TenantRegistrationMode controls public tenant onboarding/management.
	// Empty defaults to "open". "bootstrap_only" disables public tenant
	// mutation routes while leaving manifest/admin/bootstrap core APIs available.
	TenantRegistrationMode RegistrationMode

	// Environment is a host-provided runtime mode string used for dev/prod behavior checks.
	// Expected values include "prod"/"production" for production, anything else is treated as non-prod.
	Environment string

	// SolanaNetwork is a host-provided Solana chain selector ("mainnet", "testnet", "devnet").
	// If empty, AuthKit derives a default from Environment.
	SolanaNetwork string

	// Keys can be nil - if nil, authkit auto-discovers keys with this priority:
	// 1. Environment variables (ACTIVE_KEY_ID, ACTIVE_PRIVATE_KEY_PEM, PUBLIC_KEYS)
	// 2. Filesystem /vault/auth/keys.json (External Secrets Operator in K8s)
	// 3. Auto-generated keys in .runtime/authkit/ (development fallback)
	Keys jwtkit.KeySource

	// Providers – identity providers by name ("google", "apple", "github", "discord").
	// Only client id/secret are required; standard scopes are derived from defaults.
	Providers map[string]oidckit.RPConfig

	// ProviderDescriptors define OAuth2/OIDC providers using config-first
	// descriptors. These augment/override built-in Providers entries and are
	// the preferred path for adding custom providers.
	ProviderDescriptors map[string]authprovider.Provider

	// ServiceTokenPrefix is the issuing application's BRAND prefix for Tenant
	// Service Tokens (service tokens). It is a single value per deployment (NOT per-tenant)
	// and a free brand choice by the host app — e.g. tensorhub sets "cozy" so
	// every service token it mints is `cozy_st_<key_id>_<secret>`. The `_st_` type
	// segment is fixed and not configurable. Empty -> bare `st_`. Must be
	// lowercase alphanumeric, 1-16 chars. A unique app prefix lets leak
	// scanners and push-protection partners identify the issuer at a glance.
	ServiceTokenPrefix string

	// ServiceTokenMaxTTL caps how far in the future a minted service token may expire.
	// 0 (default) means no cap (tokens may be non-expiring). When set, a
	// requested expiry beyond now+MaxTTL — including a null/no-expiry request —
	// is capped to now+MaxTTL at mint time.
	ServiceTokenMaxTTL time.Duration

	// ResourceScopeAuthorizer optionally authorizes host-defined service token resource
	// scopes during HTTP minting. AuthKit validates only shape/length and stores
	// resource Kind/ID pairs opaquely; the embedding host owns semantic
	// no-escalation such as "may this caller mint openrails.tenant_subject=cozy-art".
	ResourceScopeAuthorizer ResourceScopeAuthorizer

	// PermissionCatalog is the embedding application's set of valid permission
	// strings (e.g. tensorhub's `endpoint:revise`, `repo:create`). authkit merges
	// this with its own base permissions (the reserved `tenant:` namespace) to form
	// the catalog it validates role/service token grants against. Permissions are opaque to
	// authkit — it never interprets their meaning. Names must not collide with
	// the reserved `tenant:` base permissions.
	PermissionCatalog []PermissionDef

	// DefaultRoles are role templates seeded into every tenant at creation, in
	// addition to the built-in `owner` role (which is always seeded with `*`).
	// e.g. tensorhub declares `admin` = {"*", "!tenant:roles:manage",
	// "!tenant:members:manage"} (everything an owner has except role + membership
	// management). Permission tokens: a concrete permission, `*` (all), or
	// `!perm` (exclude).
	DefaultRoles []DefaultRole
}

// PermissionDef is one entry in the permission catalog: an opaque permission
// string plus a human-readable description (surfaced to admin UIs).
type PermissionDef struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// DefaultRole is a role template seeded into every tenant at creation: a role name
// and its permission set (tokens may include `*` and `!perm` exclusions).
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
	RegistrationModeOpen          RegistrationMode = "open"
	RegistrationModeBootstrapOnly RegistrationMode = "bootstrap_only"
)
