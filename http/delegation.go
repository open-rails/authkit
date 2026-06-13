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
// delegated service token.
const DelegatedAccessTokenType = jwtkit.DelegatedAccessTokenType

// AccessTokenType is the canonical JOSE `typ` header value for an AuthKit
// service token.
const AccessTokenType = jwtkit.AccessTokenType

// DelegatedAccessParams describes a delegated service token to mint.
//
// A delegated service token is AuthKit's standard primitive for resource-service
// federation: one AuthKit issuer signs a short-lived JWT for an external
// (delegated) actor, and a resource service accepts it after issuer/JWKS/
// audience validation. The token represents a delegated actor
// (DelegatedSubject) acting under the resource account that the VALIDATED
// `iss` resolves to in the receiver's issuer registry — the token itself
// carries no tenant claims. It NEVER carries a normal `sub` — no local account
// is implied in the receiving service.
type DelegatedAccessParams struct {
	// Issuer becomes the `iss` claim: the AuthKit issuer that signed the token.
	// signs the token. Must match a tenant issuer registered with the
	// validating resource server. Required.
	Issuer string
	// Audiences becomes the `aud` claim: the target resource API(s), e.g.
	// "openrails", "tensorhub", or "gen-orchestrator".
	Audiences []string
	// There is NO tenant claim of any kind on a delegated access token (hard
	// cut): the VALIDATED `iss` IS the tenant identity. The receiver's issuer
	// registry maps the issuer to exactly one internal tenant record (slug +
	// uuid), so neither identifier ever rides in the token — a host's complete
	// identity is its issuer URL and signing key.
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
	// Roles is a convenience for emitting the actor's role UUIDs into
	// `attributes.roles` (a JSON array of UUID strings). Verify lifts them onto
	// DelegatedPrincipal.Roles (validated + capped). Equivalent to setting
	// Attributes["roles"] yourself; when both are set this typed field wins.
	// authkit does not validate UUID shape at mint — that happens at verify.
	Roles []string
	// TTL is the token lifetime. Defaults to 15m when zero.
	TTL time.Duration
	// JTI, when set, becomes the `jti` claim (token identifier). Optional.
	JTI string
	// NotBefore, when set, becomes the `nbf` claim. Optional.
	NotBefore time.Time
}

// MintDelegatedAccessToken signs a canonical delegated service token. It stamps
// the `typ=delegated-access+jwt` JOSE header, writes the canonical
// `delegated_sub`/`permissions`/`attributes` claims, and NEVER sets
// `sub` — the
// sub-XOR-delegated_sub invariant is enforced by construction. Receiving
// services authorize by issuer/resource-account trust plus `permissions`. A
// top-level `roles` claim is never minted (it is forbidden on this profile);
// actor role UUIDs, when carried, ride under `attributes.roles` (see the Roles
// param) as opaque scope keys, not as authority for the receiving service.
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
	// Merge the typed Roles convenience into attributes.roles (typed field wins
	// over any Attributes["roles"] the caller also set). Drop blanks so callers
	// can't smuggle empty role strings.
	attributes := p.Attributes
	if len(p.Roles) > 0 {
		roles := make([]string, 0, len(p.Roles))
		for _, r := range p.Roles {
			if s := strings.TrimSpace(r); s != "" {
				roles = append(roles, s)
			}
		}
		if len(roles) > 0 {
			if attributes == nil {
				attributes = make(map[string]any, 1)
			} else {
				// Copy so we don't mutate the caller's map.
				cp := make(map[string]any, len(attributes)+1)
				for k, vv := range attributes {
					cp[k] = vv
				}
				attributes = cp
			}
			attributes["roles"] = roles
		}
	}
	if len(attributes) > 0 {
		claims["attributes"] = attributes
	}
	if j := strings.TrimSpace(p.JTI); j != "" {
		claims["jti"] = j
	}
	if !p.NotBefore.IsZero() {
		claims["nbf"] = p.NotBefore.Unix()
	}
	// Invariant: a delegated service token must never carry `sub`.
	delete(claims, "sub")

	headers := map[string]any{"typ": DelegatedAccessTokenType}
	if hs, ok := signer.(jwtkit.HeaderSigner); ok {
		return hs.SignWithHeaders(ctx, claims, headers)
	}
	return "", errors.New("header signer required")
}
