package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	jwtkit "github.com/open-rails/authkit/jwt"
)

const (
	// ServiceJWTTokenUse is the required `token_use` claim for service JWTs.
	ServiceJWTTokenUse = "service"
	// ServiceJWTType is the JOSE typ header AuthKit stamps on minted service JWTs.
	ServiceJWTType = "service+jwt"
	// DefaultServiceJWTLifetime is the recommended lifetime for first-party
	// machine-to-machine service JWTs.
	DefaultServiceJWTLifetime = 15 * time.Minute
)

var (
	ErrInvalidServiceJWT = errors.New("invalid_service_jwt")
	ErrMissingSigner     = errors.New("missing_signer")
)

// ServiceJWTClaims is the canonical AuthKit claim shape for caller-minted
// machine-to-machine JWTs. Permissions are requested capabilities; receiving
// services must still intersect them with server-side grants.
type ServiceJWTClaims struct {
	Issuer      string
	Subject     string
	Audiences   []string
	IssuedAt    time.Time
	NotBefore   time.Time
	ExpiresAt   time.Time
	JTI         string
	TokenUse    string
	Permissions []string
	Resources   []ServiceTokenResource
	Scope       []string
}

// ServiceJWTMintOptions controls service-JWT minting for embedded hosts.
type ServiceJWTMintOptions struct {
	Subject     string
	Audiences   []string
	Permissions []string
	Resources   []ServiceTokenResource
	Lifetime    time.Duration
	NotBefore   time.Time
	IssuedAt    time.Time
	JTI         string
}

// MintServiceJWT creates a short-lived signed service JWT from AuthKit's active
// signing key. It defaults to a 15-minute lifetime and stamps
// `token_use=service`; it does not grant host permissions by itself.
func (s *Service) MintServiceJWT(ctx context.Context, opts ServiceJWTMintOptions) (string, ServiceJWTClaims, error) {
	signer := s.keys.Active
	if signer == nil {
		return "", ServiceJWTClaims{}, ErrMissingSigner
	}
	return MintServiceJWT(ctx, signer, strings.TrimSpace(s.opts.Issuer), opts)
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
	resources, err := normalizeServiceTokenResources(opts.Resources)
	if err != nil {
		return "", ServiceJWTClaims{}, err
	}
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
	if len(resources) > 0 {
		claims["resources"] = resources
	}
	var (
		token string
	)
	if hs, ok := signer.(jwtkit.HeaderSigner); ok {
		token, err = hs.SignWithHeaders(ctx, claims, map[string]any{"typ": ServiceJWTType})
	} else {
		token, err = signer.Sign(ctx, claims)
	}
	if err != nil {
		return "", ServiceJWTClaims{}, err
	}
	return token, ServiceJWTClaims{
		Issuer: issuer, Subject: subject, Audiences: audiences,
		IssuedAt: now, NotBefore: nbf, ExpiresAt: exp, JTI: jti,
		TokenUse: ServiceJWTTokenUse, Permissions: permissions, Resources: resources,
	}, nil
}

func randomServiceJWTID() (string, error) {
	var b [18]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
