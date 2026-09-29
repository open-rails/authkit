package engine

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/jwtkit"
)

// MintRemoteApplicationAccessToken signs a remote-application access token
// with this deployment's key: this deployment acting as an application
// registered elsewhere. An empty p.Issuer is this deployment's issuer.
func (s *Engine) MintRemoteApplicationAccessToken(ctx context.Context, p iam.RemoteApplicationAccess) (iam.Token, error) {
	signer := s.keys.ActiveSigner()
	if signer == nil {
		return iam.Token{}, iam.ErrMissingSigner
	}
	if strings.TrimSpace(p.Issuer) == "" {
		p.Issuer = strings.TrimSpace(s.cfg.Token.Issuer)
	}
	return MintRemoteApplicationAccessToken(ctx, signer, p)
}

// MintRemoteApplicationAccessToken signs a remote-application access token
// with an explicit signer: typ remote-application-access+jwt and no sub or
// delegated_sub. Identity is the issuer and authority is stored by the
// verifier; a non-nil p.Permissions only narrows it.
func MintRemoteApplicationAccessToken(ctx context.Context, signer jwtkit.Signer, p iam.RemoteApplicationAccess) (iam.Token, error) {
	if signer == nil {
		return iam.Token{}, iam.ErrMissingSigner
	}
	if strings.TrimSpace(p.Issuer) == "" {
		return iam.Token{}, errors.New("issuer required")
	}
	ttl := p.TTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	now := time.Now()
	exp := now.Add(ttl)
	claims := jwt.MapClaims{
		"iss": strings.TrimSpace(p.Issuer),
		"iat": now.Unix(),
		"exp": exp.Unix(),
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
	// Non-nil narrows, even to nothing; nil claims the full stored authority.
	if p.Permissions != nil {
		claims["permissions"] = p.Permissions
	}
	token, err := jwtkit.SignWithType(ctx, signer, claims, jwtkit.RemoteApplicationAccessTokenType, true)
	if err != nil {
		return iam.Token{}, err
	}
	return iam.Token{Value: token, ExpiresAt: exp}, nil
}
