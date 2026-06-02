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

	// OrgMode controls multi-organization behavior.
	// Valid values: "single" (default) or "multi".
	OrgMode string

	// PublicRegistrationDisabled, when true, turns off all PUBLIC user
	// self-registration and auto-registration paths: password registration,
	// availability, resend, OIDC/social/Solana/passkey auto-create, and
	// pending-registration confirmation. Existing-user authentication (login,
	// refresh, logout, password reset/recovery, verification, sessions) is
	// unaffected, and embedded bootstrap/admin/internal creation via the
	// exported CreateUser / ImportUser core APIs still works.
	//
	// Default false preserves current behavior (public registration enabled).
	PublicRegistrationDisabled bool

	// PublicOrgManagementDisabled, when true, denies the PUBLIC org-facing
	// onboarding/management HTTP routes (org creation, rename, invites, member
	// changes, role changes, OAT management). Embedded core/bootstrap code can
	// still ensure the initial orgs, roles, admin membership, and OATs through
	// the exported core APIs (CreateOrg, AssignRole, OAT minting, etc.).
	//
	// Default false preserves current behavior (public org management enabled).
	PublicOrgManagementDisabled bool

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

	// TokenPrefix is the issuing application's BRAND prefix for Organization
	// Access Tokens (OATs). It is a single value per deployment (NOT per-org)
	// and a free brand choice by the host app — e.g. tensorhub sets "cozy" so
	// every OAT it mints is `cozy_oat_<key_id>_<secret>`. The `_oat_` type
	// segment is fixed and not configurable. Empty -> bare `oat_`. Must be
	// lowercase alphanumeric, 1-16 chars. A unique app prefix lets leak
	// scanners and push-protection partners identify the issuer at a glance.
	TokenPrefix string

	// OrgAccessTokenMaxTTL caps how far in the future a minted OAT may expire.
	// 0 (default) means no cap (tokens may be non-expiring). When set, a
	// requested expiry beyond now+MaxTTL — including a null/no-expiry request —
	// is capped to now+MaxTTL at mint time.
	OrgAccessTokenMaxTTL time.Duration

	// PermissionCatalog is the embedding application's set of valid permission
	// strings (e.g. tensorhub's `endpoint:revise`, `repo:create`). authkit merges
	// this with its own base permissions (the reserved `org:` namespace) to form
	// the catalog it validates role/OAT grants against. Permissions are opaque to
	// authkit — it never interprets their meaning. Names must not collide with
	// the reserved `org:` base permissions.
	PermissionCatalog []PermissionDef

	// DefaultRoles are role templates seeded into every org at creation, in
	// addition to the built-in `owner` role (which is always seeded with `*`).
	// e.g. tensorhub declares `admin` = {"*", "!org:roles:manage",
	// "!org:members:manage"} (everything an owner has except role + membership
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

// DefaultRole is a role template seeded into every org at creation: a role name
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
