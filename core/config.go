package core

import (
	"time"

	jwtkit "github.com/PaulFidika/authkit/jwt"
	oidckit "github.com/PaulFidika/authkit/oidc"
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

	// Keys can be nil - if nil, authkit auto-discovers keys with this priority:
	// 1. Environment variables (ACTIVE_KEY_ID, ACTIVE_PRIVATE_KEY_PEM, PUBLIC_KEYS)
	// 2. Filesystem /vault/auth/keys.json (External Secrets Operator in K8s)
	// 3. Auto-generated keys in .runtime/authkit/ (development fallback)
	Keys jwtkit.KeySource

	// Providers – identity providers by name ("google", "apple", "github", "discord").
	// Only client id/secret are required; standard scopes are derived from defaults.
	Providers map[string]oidckit.RPConfig
}
