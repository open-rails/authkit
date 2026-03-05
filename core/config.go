package core

import (
	"time"

	jwtkit "github.com/open-rails/authkit/jwt"
	oidckit "github.com/open-rails/authkit/oidc"
)

// Config mirrors the simplicity of go-pkgz/auth: provide issuer, durations, and keys.
type Config struct {
	Issuer          string
	IssuedAudiences []string // JWT audiences - tokens issued will contain ALL of these audiences
	// ExpectedAudiences enforces that verified access tokens contain at least one
	// of these audiences. Prefer this over ExpectedAudience for new integrations.
	ExpectedAudiences []string
	// ExpectedAudience enforces a single required audience for verified access tokens.
	// Deprecated: prefer ExpectedAudiences.
	ExpectedAudience     string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	// Session limits
	SessionMaxPerUser int // 0 = unlimited, default 3 if unset by service; eviction is always evict-oldest
	// Optional: if set, used for building absolute URLs (e.g., password reset/verify links).
	BaseURL string
	// Paths for reset/verify are fixed to "/reset" and "/verify"; not configurable.

	// RequireVerifiedRegistrations controls whether email/phone registration requires
	// confirmation before the account is usable.
	// Default behavior in NewFromConfig is true when this is nil.
	RequireVerifiedRegistrations *bool
	// VerificationRequired is deprecated. Use RequireVerifiedRegistrations.
	// Backward compatibility note: this legacy field only influences config when set to true.
	VerificationRequired bool

	// OrgMode controls multi-organization behavior.
	// Valid values: "single" (default) or "multi".
	OrgMode string

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
}

// Bool returns a pointer to v for convenient Config field assignment.
func Bool(v bool) *bool { return &v }
