package authcore

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	authkit "github.com/open-rails/authkit"
	jwtkit "github.com/open-rails/authkit/jwt"
)

const (
	// ServiceJWTTokenUse + DefaultServiceJWTLifetime are defined in authkit
	// (core-free) and re-exported here.
	ServiceJWTTokenUse = authkit.ServiceJWTTokenUse
	// ServiceJWTType is the JOSE typ header AuthKit stamps on minted service JWTs.
	ServiceJWTType            = "service+jwt"
	DefaultServiceJWTLifetime = authkit.DefaultServiceJWTLifetime
)

var (
	// ErrInvalidServiceJWT is defined in authkit and re-exported here.
	ErrInvalidServiceJWT = authkit.ErrInvalidServiceJWT
	ErrMissingSigner     = authkit.ErrMissingSigner
)

// ServiceJWTClaims is defined in authkit (core-free) and re-exported here.
type ServiceJWTClaims = authkit.ServiceJWTClaims

// ServiceJWTMintOptions controls service-JWT minting for embedded hosts.
type ServiceJWTMintOptions = authkit.ServiceJWTMintOptions

// MintServiceJWT creates a short-lived signed service JWT from AuthKit's active
// signing key. It defaults to a 15-minute lifetime and stamps
// `token_use=service`; it does not grant host permissions by itself.
func (s *Service) MintServiceJWT(ctx context.Context, opts ServiceJWTMintOptions) (string, ServiceJWTClaims, error) {
	signer := s.keys.Active
	if signer == nil {
		return "", ServiceJWTClaims{}, ErrMissingSigner
	}
	return MintServiceJWT(ctx, signer, strings.TrimSpace(s.cfg.Token.Issuer), opts)
}

// MintServiceJWT signs a service JWT with an explicit signer and issuer. Hosts
// can use this helper when they manage the signing key outside core.Service.
func MintServiceJWT(ctx context.Context, signer jwtkit.Signer, issuer string, opts ServiceJWTMintOptions) (string, ServiceJWTClaims, error) {
	if signer == nil {
		return "", ServiceJWTClaims{}, ErrMissingSigner
	}
	issuer = strings.TrimSpace(issuer)
	subject := strings.TrimSpace(opts.Subject)
	audiences := dedupeStrings(opts.Audiences)
	if issuer == "" || subject == "" || len(audiences) == 0 {
		return "", ServiceJWTClaims{}, ErrInvalidServiceJWT
	}
	permissions := dedupeStrings(opts.Permissions)
	now := opts.IssuedAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nbf := opts.NotBefore.UTC()
	if nbf.IsZero() {
		nbf = now
	}
	lifetime := opts.Lifetime
	if lifetime <= 0 {
		lifetime = DefaultServiceJWTLifetime
	}
	if lifetime > DefaultServiceJWTLifetime {
		lifetime = DefaultServiceJWTLifetime
	}
	jti := strings.TrimSpace(opts.JTI)
	if jti == "" {
		var err error
		jti, err = randomServiceJWTID()
		if err != nil {
			return "", ServiceJWTClaims{}, err
		}
	}
	exp := now.Add(lifetime)

	claims := jwt.MapClaims{
		"iss":         issuer,
		"sub":         subject,
		"aud":         audiences,
		"iat":         now.Unix(),
		"nbf":         nbf.Unix(),
		"exp":         exp.Unix(),
		"jti":         jti,
		"token_use":   ServiceJWTTokenUse,
		"permissions": permissions,
	}
	token, err := jwtkit.SignWithType(ctx, signer, claims, ServiceJWTType, false)
	if err != nil {
		return "", ServiceJWTClaims{}, err
	}
	return token, ServiceJWTClaims{
		Issuer: issuer, Subject: subject, Audiences: audiences,
		IssuedAt: now, NotBefore: nbf, ExpiresAt: exp, JTI: jti,
		TokenUse: ServiceJWTTokenUse, Permissions: permissions,
	}, nil
}

func randomServiceJWTID() (string, error) {
	var b [18]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
