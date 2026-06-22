package authhttp

import (
	"github.com/open-rails/authkit/verify"
)

// The verification layer — Verifier, Claims, and the Required/Optional
// middleware — lives in the core-free github.com/open-rails/authkit/verify
// package (#110) so a verify-only consumer can validate tokens without pulling
// in Postgres/Redis/the storage stack. These aliases re-export that surface
// under authhttp unchanged, so existing embedders that import authhttp keep
// compiling with zero churn.

type (
	Verifier                = verify.Verifier
	Claims                  = verify.Claims
	VerifierOption          = verify.VerifierOption
	IssuerOptions           = verify.IssuerOptions
	IssuerKey               = verify.IssuerKey
	Enricher                = verify.Enricher
	DelegatedPrincipal      = verify.DelegatedPrincipal
	PermissionValidator     = verify.PermissionValidator
	AttributesValidator     = verify.AttributesValidator
	AttributeDefResolver    = verify.AttributeDefResolver
	RemoteApplicationSource = verify.RemoteApplicationSource

	ServiceJWTPrincipal     = verify.ServiceJWTPrincipal
	ServiceJWTReplayChecker = verify.ServiceJWTReplayChecker
	ServiceJWTVerifyOption  = verify.ServiceJWTVerifyOption
)

const (
	ServicePrincipalType       = verify.ServicePrincipalType
	RemoteApplicationTokenType = verify.RemoteApplicationTokenType
)

var (
	NewVerifier            = verify.NewVerifier
	Required               = verify.Required
	Optional               = verify.Optional
	RequireEntitlement     = verify.RequireEntitlement
	RequireAnyEntitlement  = verify.RequireAnyEntitlement
	ClaimsFromContext      = verify.ClaimsFromContext
	WithSkew               = verify.WithSkew
	WithAlgorithms         = verify.WithAlgorithms
	WithHTTPClient         = verify.WithHTTPClient
	WithSSRFGuard          = verify.WithSSRFGuard
	WithAPIKeyPrefix       = verify.WithAPIKeyPrefix
	WithPermissions        = verify.WithPermissions
	WithAttributesPolicy   = verify.WithAttributesPolicy
	WithAttributeHydration = verify.WithAttributeHydration

	RequiredServiceJWT             = verify.RequiredServiceJWT
	ServiceJWTPrincipalFromContext = verify.ServiceJWTPrincipalFromContext
	WithServiceJWTMaxLifetime      = verify.WithServiceJWTMaxLifetime
	WithServiceJWTReplayChecker    = verify.WithServiceJWTReplayChecker
	RemoteApplicationCORS          = verify.RemoteApplicationCORS
	RequireDelegatedOrigin         = verify.RequireDelegatedOrigin
	NewSSRFGuardedClient           = verify.NewSSRFGuardedClient

	// lowercase alias so staying authhttp handlers keep calling remoteAppOptions.
	remoteAppOptions = verify.RemoteAppOptions
	// lowercase alias so the delegated-roles test keeps referencing the cap.
	maxDelegatedRoles = verify.MaxDelegatedRoles

	// Internal context helpers used by other authhttp handlers (logout,
	// sessions). The canonical definitions moved to verify with claims.go.
	setClaims = verify.SetClaims
	getClaims = verify.GetClaims
)
