package engine

import (
	"context"
	"errors"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/secret"
)

func (s *Engine) proofRouteKey(kind, hash string) string {
	return "auth-proof-route:" + secret.Hash(s.cfg.Token.Issuer+"\x00"+kind+"\x00"+hash)
}

// This is an immutable routing hint, not a credential. The actual proof in
// its tenant's store remains authoritative and single use. Keep the hint until
// expiry so an invalid attempt cannot consume a real owner's proof.
func (s *Engine) rememberProofRoute(ctx context.Context, kind, hash string, ttl time.Duration) error {
	id, err := s.tenantID(ctx)
	if err != nil {
		return err
	}
	key, value := s.proofRouteKey(kind, hash), []byte(id.String())
	if ok, err := s.ephemeral.Swap(ctx, key, nil, value, ttl); err != nil || ok {
		return err
	}
	old, ok, err := s.ephemeral.Get(ctx, key)
	if err != nil {
		return err
	}
	if !ok || string(old) != string(value) {
		return jwt.ErrTokenUnverifiable
	}
	return nil
}

func (s *Engine) proofContext(ctx context.Context, kind, hash string) (context.Context, error) {
	if _, err := s.tenantID(ctx); err == nil {
		return ctx, nil
	} else if !errors.Is(err, iam.ErrTenantRequired) {
		return nil, err
	}
	value, ok, err := s.ephemeral.Get(ctx, s.proofRouteKey(kind, hash))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, jwt.ErrTokenUnverifiable
	}
	id, err := iam.ParseTenantID(string(value))
	if err != nil {
		return nil, jwt.ErrTokenUnverifiable
	}
	return WithTenant(ctx, id), nil
}
