package authkit

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/jwtkit"
)

const (

	// ServiceJWTType is the JOSE typ header AuthKit stamps on minted service JWTs.
	serviceJWTType = "service+jwt"
)

// MintServiceJWT creates a short-lived signed service JWT from AuthKit's active
// signing key. It defaults to a 15-minute lifetime and stamps
// `token_use=service`; it does not grant host permissions by itself.
func (s *engine) MintServiceJWT(ctx context.Context, opts iam.ServiceJWTMintOptions) (string, iam.ServiceJWTClaims, error) {
	signer := s.keys.ActiveSigner()
	if signer == nil {
		return "", iam.ServiceJWTClaims{}, iam.ErrMissingSigner
	}
	return MintServiceJWT(ctx, signer, strings.TrimSpace(s.cfg.Token.Issuer), opts)
}

// MintServiceJWT signs a service JWT with an explicit signer and issuer. Hosts
// can use this helper when they manage the signing key outside AuthKit.
func MintServiceJWT(ctx context.Context, signer jwtkit.Signer, issuer string, opts iam.ServiceJWTMintOptions) (string, iam.ServiceJWTClaims, error) {
	if signer == nil {
		return "", iam.ServiceJWTClaims{}, iam.ErrMissingSigner
	}
	issuer = strings.TrimSpace(issuer)
	subject := strings.TrimSpace(opts.Subject)
	audiences := dedupeStrings(opts.Audiences)
	if issuer == "" || subject == "" || len(audiences) == 0 {
		return "", iam.ServiceJWTClaims{}, iam.ErrInvalidServiceJWT
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
		lifetime = iam.DefaultServiceJWTLifetime
	}
	if lifetime > iam.DefaultServiceJWTLifetime {
		lifetime = iam.DefaultServiceJWTLifetime
	}
	jti := strings.TrimSpace(opts.JTI)
	if jti == "" {
		var err error
		jti, err = randomServiceJWTID()
		if err != nil {
			return "", iam.ServiceJWTClaims{}, err
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
		"token_use":   iam.ServiceJWTTokenUse,
		"permissions": permissions,
	}
	token, err := jwtkit.SignWithType(ctx, signer, claims, serviceJWTType, false)
	if err != nil {
		return "", iam.ServiceJWTClaims{}, err
	}
	return token, iam.ServiceJWTClaims{
		Issuer: issuer, Subject: subject, Audiences: audiences,
		IssuedAt: now, NotBefore: nbf, ExpiresAt: exp, JTI: jti,
		TokenUse: iam.ServiceJWTTokenUse, Permissions: permissions,
	}, nil
}

func randomServiceJWTID() (string, error) {
	var b [18]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
