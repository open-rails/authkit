package authcore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/jwtkit"
)

// DelegatedAccessTokenType is the canonical JOSE `typ` header value for a
// delegated access token.
const DelegatedAccessTokenType = jwtkit.DelegatedAccessTokenType

// DelegatedAccessParams describes a delegated access token to mint.
//
// A delegated access token is AuthKit's standard primitive for resource-service
// federation: one AuthKit issuer signs a short-lived JWT for an external
// delegated subject, and a resource service accepts it after issuer/JWKS/
// audience validation. The token represents a delegated subject
// (DelegatedSubject) acting under the resource account that the VALIDATED
// `iss` resolves to in the receiver's issuer registry. It NEVER carries a
// normal `sub` — no local account is implied in the receiving service.
type DelegatedAccessParams = authkit.DelegatedAccessParams

// MintDelegatedAccessToken signs a canonical delegated access token using the
// Service's internal signer. The host passes claims/params only and NEVER
// touches the private key. When p.Issuer is empty it defaults to the Service's
// configured Issuer. See the package-level MintDelegatedAccessToken for the
// claim contract.
func (s *Service) MintDelegatedAccessToken(ctx context.Context, p DelegatedAccessParams) (string, error) {
	signer := s.keys.ActiveSigner()
	if signer == nil {
		return "", ErrMissingSigner
	}
	if strings.TrimSpace(p.Issuer) == "" {
		p.Issuer = strings.TrimSpace(s.cfg.Token.Issuer)
	}
	return MintDelegatedAccessToken(ctx, signer, p)
}

// MintDelegatedAccessToken signs a canonical delegated access token with an
// explicit signer. It stamps the `typ=delegated-access+jwt` JOSE header, writes
// the canonical `delegated_sub`/`permissions`/`attributes` claims, and NEVER
// sets `sub` — the sub-XOR-delegated_sub invariant is enforced by construction.
// Receiving services authorize by issuer/resource-account trust plus
// `permissions`. A top-level `roles` claim is never minted; delegated-subject
// role UUIDs, when carried, ride under `attributes.roles` (see the Roles param).
//
// Hosts embedding core.Service should prefer (*Service).MintDelegatedAccessToken
// so they never construct their own signer or read the PEM.
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
	references, err := documents.NormalizeReferences(p.Documents)
	if err != nil {
		return "", err
	}
	if _, shadowsTopLevel := p.Attributes["documents"]; shadowsTopLevel {
		return "", fmt.Errorf("%w: attributes.documents is reserved", documents.ErrReservedAttribute)
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
	if len(references) > 0 {
		claims["documents"] = references
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
	// Invariant: a delegated access token must never carry `sub`.
	delete(claims, "sub")

	return jwtkit.SignWithType(ctx, signer, claims, DelegatedAccessTokenType, true)
}
