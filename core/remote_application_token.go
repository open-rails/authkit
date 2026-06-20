package core

import (
	"context"
	"errors"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	jwtkit "github.com/open-rails/authkit/jwt"
)

// RemoteApplicationAccessTokenType is the JOSE `typ` for a remote application
// access token.
const RemoteApplicationAccessTokenType = jwtkit.RemoteApplicationAccessTokenType

// Programmatic access — two credential types, both STORED-authority (#76):
//
//   - API key: a shared secret; we
//     store sha256(secret) + its assigned permissions.
//   - remote application access token (this file): a remote_application signs a
//     JWT with typ=remote-application-access+jwt; we verify it against the
//     application's registered JWKS and grant the authority WE ASSIGNED
//     (org role membership only, #95), NEVER what role claims in the token
//     self-assert.
//
// This stored-authority token is the canonical remote application "act as
// myself by assigned role/permission" model. The #70/#73 service-JWT
// (core/service_jwt.go, MintServiceJWT/MintCustomJWT) carries permissions ON
// the token and remains ADDITIVE/unchanged here — tensorhub/cozy-art depend on
// it. It MAY be deprecated in a later issue in favor of stored authority; do
// not remove it.

// RemoteApplicationAccessParams describes a remote application access token to
// mint (#76): a remote_application signs a short-lived JWT that authenticates it
// AS ITSELF. The principal's authority is the STORED set AuthKit assigned it
// (org role membership only, #95), resolved at verify from the validated
// `iss`. The token therefore carries NO authority role claims of its own — and
// even if a caller adds them, the verifier ignores them.
type RemoteApplicationAccessParams struct {
	// Issuer becomes the `iss` claim: the remote_application's OIDC issuer,
	// registered with the validating resource server. Required when minting via
	// the free function; the *Service mint method defaults it to the Service's
	// configured Issuer when empty.
	Issuer string
	// Audiences becomes the `aud` claim: the target resource API(s).
	Audiences []string
	// TTL is the token lifetime. Defaults to 15m when zero.
	TTL time.Duration
	// JTI, when set, becomes the `jti` claim. Optional.
	JTI string
	// NotBefore, when set, becomes the `nbf` claim. Optional.
	NotBefore time.Time
	// Permissions, when non-nil, becomes the `permissions` claim: a DOWN-SCOPING
	// request for least-privilege (#76 amendment). The stored grant is the
	// ceiling; effective = this claim, but EVERY claimed perm must be within the
	// stored grant — an out-of-grant claimed perm REJECTS the token at verify (a
	// remote application access token can never widen). nil/absent => no claim
	// => full stored ceiling (backward-compatible with v0.28.0 tokens).
	Permissions []string
}

// MintRemoteApplicationAccessToken signs a remote application access token using the
// Service's internal signer. When p.Issuer is empty it defaults to the Service's
// configured Issuer.
func (s *Service) MintRemoteApplicationAccessToken(ctx context.Context, p RemoteApplicationAccessParams) (string, error) {
	signer := s.keys.Active
	if signer == nil {
		return "", ErrMissingSigner
	}
	if strings.TrimSpace(p.Issuer) == "" {
		p.Issuer = strings.TrimSpace(s.opts.Issuer)
	}
	return MintRemoteApplicationAccessToken(ctx, signer, p)
}

// MintRemoteApplicationAccessToken signs a remote application access token with an
// explicit signer. It stamps the `typ=remote-application-access+jwt` header and
// writes NO `sub`/`delegated_sub` — identity is the validated `iss` and authority
// is STORED, resolved at verify. A non-nil p.Permissions is written as the
// `permissions` claim: a down-scoping request the verifier intersects with the
// stored ceiling (#76 amendment); never a widening.
func MintRemoteApplicationAccessToken(ctx context.Context, signer jwtkit.Signer, p RemoteApplicationAccessParams) (string, error) {
	if signer == nil {
		return "", errors.New("signer required")
	}
	if strings.TrimSpace(p.Issuer) == "" {
		return "", errors.New("issuer required")
	}
	ttl := p.TTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": strings.TrimSpace(p.Issuer),
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	}
	if len(p.Audiences) > 0 {
		claims["aud"] = p.Audiences
	}
	if j := strings.TrimSpace(p.JTI); j != "" {
		claims["jti"] = j
	}
	if !p.NotBefore.IsZero() {
		claims["nbf"] = p.NotBefore.Unix()
	}
	// Non-nil => a down-scoping claim (even empty = narrow to nothing). nil = no claim.
	if p.Permissions != nil {
		claims["permissions"] = p.Permissions
	}
	// Invariant: this token implies no local user or delegated actor.
	delete(claims, "sub")
	delete(claims, "delegated_sub")

	headers := map[string]any{"typ": RemoteApplicationAccessTokenType}
	if hs, ok := signer.(jwtkit.HeaderSigner); ok {
		return hs.SignWithHeaders(ctx, claims, headers)
	}
	return "", errors.New("header signer required")
}
