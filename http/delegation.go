package authhttp

import (
	"context"
	"errors"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	jwtkit "github.com/open-rails/authkit/jwt"
)

// DelegatedTokenParams describes a delegated platform token to mint. The token
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
	UserTier string
	// Roles becomes `roles` (platform-scoped roles for this user).
	Roles []string
	// TTL is the token lifetime. Defaults to 15m when zero.
	TTL time.Duration
}

// MintDelegatedToken signs a delegated platform token. It NEVER sets `sub` — the
// federated user is carried in `delegated_sub` — so a validating authkit will
// treat it as a DelegatedPrincipal and skip the local-user gate. The
// `sub` XOR `delegated_sub` invariant is enforced by construction here.
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

	return signer.Sign(ctx, claims)
}
