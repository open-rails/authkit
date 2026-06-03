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
// delegated access token.
const DelegatedAccessTokenType = jwtkit.DelegatedAccessTokenType

// AccessTokenType is the canonical JOSE `typ` header value for an AuthKit
// access token.
const AccessTokenType = jwtkit.AccessTokenType

// DelegatedAccessParams describes a delegated access token to mint.
//
// A delegated access token is AuthKit's standard primitive for resource-service
// federation: one AuthKit issuer signs a short-lived JWT for an external
// (delegated) actor, and a resource service accepts it after issuer/JWKS/
// audience/resource-account validation. The token represents a delegated actor
// (DelegatedSubject) acting under a target resource account carried in the
// `tenant` JWT claim. It NEVER carries a normal `sub` — no local account is
// implied in the receiving service.
type DelegatedAccessParams struct {
	// Issuer becomes the `iss` claim: the AuthKit issuer that signed the token.
	// signs the token. Must match a federated issuer registered with the
	// validating resource server. Required.
	Issuer string
	// Audiences becomes the `aud` claim: the target resource API(s), e.g.
	// "openrails", "tensorhub", or "gen-orchestrator".
	Audiences []string
	// Tenant becomes the `tenant` claim: the target resource-service account
	// slug or identifier, e.g. "doujins" for OpenRails.
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
}

// MintDelegatedAccessToken signs a canonical delegated access token. It stamps
// the `typ=delegated-access+jwt` JOSE header, writes the canonical
// `tenant`/`delegated_sub`/`permissions`/`attributes` claims, and NEVER sets
// `sub` — the
// sub-XOR-delegated_sub invariant is enforced by construction. Receiving
// services authorize by issuer/resource-account trust plus `permissions`;
// `roles` are not minted here because they are not authority for the receiving
// service.
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
	return "", errors.New("header signer required")
}
