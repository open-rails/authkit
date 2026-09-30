package engine

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/ops"
	"github.com/open-rails/authkit/keys"
)

// MintServiceJWT signs a short-lived service JWT with this deployment's key.
// It stamps token_use=service and grants nothing AuthKit enforces.
func (s *Engine) MintServiceJWT(ctx context.Context, opts iam.ServiceJWT, options ...ops.Option) (iam.Token, iam.ServiceJWTClaims, error) {
	if err := noOptions("MintServiceJWT", options); err != nil {
		return iam.Token{}, iam.ServiceJWTClaims{}, err
	}
	signer := s.keys.ActiveSigner()
	if signer == nil {
		return iam.Token{}, iam.ServiceJWTClaims{}, iam.ErrSigningNotConfigured
	}
	return mintServiceJWT(ctx, signer, strings.TrimSpace(s.cfg.Token.Issuer), opts)
}

func mintServiceJWT(ctx context.Context, signer keys.Signer, issuer string, opts iam.ServiceJWT) (iam.Token, iam.ServiceJWTClaims, error) {
	if signer == nil {
		return iam.Token{}, iam.ServiceJWTClaims{}, iam.ErrSigningNotConfigured
	}
	issuer = strings.TrimSpace(issuer)
	subject := strings.TrimSpace(opts.Subject)
	audiences := dedupeStrings(opts.Audiences)
	if issuer == "" || subject == "" || len(audiences) == 0 {
		return iam.Token{}, iam.ServiceJWTClaims{}, iam.ErrInvalidServiceJWT
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
	lifetime := opts.TTL
	if lifetime <= 0 || lifetime > iam.DefaultServiceJWTLifetime {
		lifetime = iam.DefaultServiceJWTLifetime
	}
	jti := strings.TrimSpace(opts.JTI)
	if jti == "" {
		var err error
		jti, err = randomServiceJWTID()
		if err != nil {
			return iam.Token{}, iam.ServiceJWTClaims{}, err
		}
	}
	exp := now.Add(lifetime)

	claims := map[string]any{
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
	token, err := jose.Sign(ctx, signer, jose.ServiceJWTType, claims)
	if err != nil {
		return iam.Token{}, iam.ServiceJWTClaims{}, err
	}
	return iam.Token{Value: token, ExpiresAt: exp}, iam.ServiceJWTClaims{
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
