package authhttp

import (
	"context"
	"errors"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	jwtkit "github.com/open-rails/authkit/jwt"
)

// DelegatedAccessTokenType is the canonical JOSE `typ` header value for a
// delegated access token, per RFC 9068-style access-token typing.
const DelegatedAccessTokenType = "at+jwt"

// DelegatedAccessParams describes a delegated access token to mint.
//
// A delegated access token is AuthKit's standard primitive for tenant/platform
// federation: one AuthKit issuer signs a short-lived JWT for an external
// (delegated) actor, and a resource service accepts it after issuer/JWKS/
// audience/tenant validation. The token represents a delegated actor
// (DelegatedSubject) acting under a canonical tenant (Tenant). It NEVER carries
// a normal `sub` — no local account is implied in the receiving service.
type DelegatedAccessParams struct {
	// Issuer becomes the `iss` claim: the tenant/platform AuthKit issuer that
	// signs the token. Must match a federated issuer registered with the
	// validating resource server. Required.
	Issuer string
	// Audiences becomes the `aud` claim: the target resource API(s), e.g.
	// "openrails", "tensorhub", or "gen-orchestrator".
	Audiences []string
	// Tenant becomes the canonical `tenant` claim: the target resource tenant/
	// platform slug or identifier. Canonical for this token class.
	Tenant string
	// DelegatedSubject becomes `delegated_sub`: the issuer-side user/actor id.
	// Required. No local account is implied in the receiving service.
	DelegatedSubject string
	// Permissions becomes the `permissions` claim: an array of resource-defined
	// permission strings (NOT OAuth's space-delimited `scope`). Receiving
	// services validate these against their own permission catalog.
	Permissions []string
	// Attributes becomes the `attributes` claim: an object of issuer-provided
	// policy metadata such as {"tier":"cozy_free"}, plan labels, budget classes,
	// or risk buckets. Values are arbitrary JSON.
	Attributes map[string]any
	// TTL is the token lifetime. Defaults to 15m when zero.
	TTL time.Duration
	// JTI, when set, becomes the `jti` claim (token identifier). Optional.
	JTI string
	// NotBefore, when set, becomes the `nbf` claim. Optional.
	NotBefore time.Time

	// CompatOrg, when true, also writes a legacy `org` claim equal to Tenant for
	// resource servers that still read `org`. The canonical `tenant` claim is
	// always written; `org` is compatibility only and MUST equal `tenant`.
	CompatOrg bool
}

// MintDelegatedAccessToken signs a canonical delegated access token. It stamps
// the `typ=at+jwt` JOSE header, writes the canonical `tenant`/`delegated_sub`/
// `permissions`/`attributes` claims, and NEVER sets `sub` — the
// sub-XOR-delegated_sub invariant is enforced by construction. Receiving
// services authorize by issuer/tenant trust plus `permissions`; `roles` are not
// minted here because they are not authority for the receiving service.
func MintDelegatedAccessToken(ctx context.Context, signer jwtkit.Signer, p DelegatedAccessParams) (string, error) {
	if signer == nil {
		return "", errors.New("signer required")
	}
	if strings.TrimSpace(p.Issuer) == "" {
		return "", errors.New("issuer required")
	}
	if strings.TrimSpace(p.DelegatedSubject) == "" {
		return "", errors.New("delegated_sub required")
	}

	ttl := p.TTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	now := time.Now()

	claims := jwt.MapClaims{
		"iss":           strings.TrimSpace(p.Issuer),
		"iat":           now.Unix(),
		"exp":           now.Add(ttl).Unix(),
		"delegated_sub": strings.TrimSpace(p.DelegatedSubject),
	}
	if len(p.Audiences) > 0 {
		claims["aud"] = p.Audiences
	}
	if t := strings.TrimSpace(p.Tenant); t != "" {
		claims["tenant"] = t
		if p.CompatOrg {
			// `org` is compatibility-only and MUST exactly equal the canonical
			// `tenant`. The verifier rejects any token where they differ.
			claims["org"] = t
		}
	}
	if len(p.Permissions) > 0 {
		// Copy + drop empties so callers can't smuggle blank permission strings.
		perms := make([]string, 0, len(p.Permissions))
		for _, perm := range p.Permissions {
			if s := strings.TrimSpace(perm); s != "" {
				perms = append(perms, s)
			}
		}
		if len(perms) > 0 {
			claims["permissions"] = perms
		}
	}
	if len(p.Attributes) > 0 {
		claims["attributes"] = p.Attributes
	}
	if j := strings.TrimSpace(p.JTI); j != "" {
		claims["jti"] = j
	}
	if !p.NotBefore.IsZero() {
		claims["nbf"] = p.NotBefore.Unix()
	}
	// Invariant: a delegated access token must never carry `sub`.
	delete(claims, "sub")

	headers := map[string]any{"typ": DelegatedAccessTokenType}
	if hs, ok := signer.(jwtkit.HeaderSigner); ok {
		return hs.SignWithHeaders(ctx, claims, headers)
	}
	// Backwards compatibility: a signer that does not implement HeaderSigner
	// still produces a valid, verifiable token — it simply omits the `typ`
	// header. Verifiers fall back to claim-shape detection in that case.
	return signer.Sign(ctx, claims)
}

// DelegatedTokenParams describes a delegated platform token to mint.
//
// Deprecated: use DelegatedAccessParams + MintDelegatedAccessToken. This type
// is retained for Tensorhub/Gen-Orchestrator backwards compatibility. The token
// represents a federated user (DelegatedSubject) acting under a federated org
// (Tenant). It is signed by the platform org's own issuer key.
type DelegatedTokenParams struct {
	// Issuer is the platform issuer URL (becomes the `iss` claim) — must match a
	// federated issuer registered with the validating resource server.
	Issuer string
	// Audiences becomes the `aud` claim (the resource servers this token targets).
	Audiences []string
	// DelegatedSubject is the federated user id (becomes `delegated_sub`). Required.
	DelegatedSubject string
	// Tenant is the federated org slug (becomes `org` + `tenant`).
	Tenant string
	// UserTier becomes `user_tier` (the platform's tier for this user).
	//
	// Deprecated: new tokens carry the tier under `attributes.tier`. This field
	// is retained so existing Tensorhub/Gen-Orchestrator callers keep working
	// during migration.
	UserTier string
	// Roles becomes `roles` (platform-scoped roles for this user).
	//
	// Deprecated: `roles` are NOT authority for the receiving service.
	Roles []string
	// TTL is the token lifetime. Defaults to 15m when zero.
	TTL time.Duration
}

// MintDelegatedToken signs a delegated platform token.
//
// Deprecated: use MintDelegatedAccessToken. It NEVER sets `sub` — the federated
// user is carried in `delegated_sub` — so a validating authkit will treat it as
// a DelegatedPrincipal and skip the local-user gate. The `sub` XOR
// `delegated_sub` invariant is enforced by construction here. This mint path
// still writes the legacy top-level `user_tier` claim and the compat `org`
// claim; new code should mint canonical delegated access tokens instead.
func MintDelegatedToken(ctx context.Context, signer jwtkit.Signer, p DelegatedTokenParams) (string, error) {
	if signer == nil {
		return "", errors.New("signer required")
	}
	if strings.TrimSpace(p.Issuer) == "" {
		return "", errors.New("issuer required")
	}
	if strings.TrimSpace(p.DelegatedSubject) == "" {
		return "", errors.New("delegated_sub required")
	}

	ttl := p.TTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	now := time.Now()

	claims := jwt.MapClaims{
		"iss":           strings.TrimSpace(p.Issuer),
		"iat":           now.Unix(),
		"exp":           now.Add(ttl).Unix(),
		"delegated_sub": strings.TrimSpace(p.DelegatedSubject),
	}
	if len(p.Audiences) > 0 {
		claims["aud"] = p.Audiences
	}
	if t := strings.TrimSpace(p.Tenant); t != "" {
		claims["org"] = t
		claims["tenant"] = t
	}
	if t := strings.TrimSpace(p.UserTier); t != "" {
		claims["user_tier"] = t
	}
	if len(p.Roles) > 0 {
		claims["roles"] = p.Roles
	}
	// Invariant: a delegated token must never carry `sub`.
	delete(claims, "sub")

	// Stamp typ=at+jwt when the signer supports it, so legacy-minted tokens are
	// also recognizable as delegated access tokens.
	headers := map[string]any{"typ": DelegatedAccessTokenType}
	if hs, ok := signer.(jwtkit.HeaderSigner); ok {
		return hs.SignWithHeaders(ctx, claims, headers)
	}
	return signer.Sign(ctx, claims)
}
