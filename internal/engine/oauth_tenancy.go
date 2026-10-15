package engine

import (
	"context"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/jose"
)

// A trusted client registration can select its directory; an explicit mount
// must match. This selection never authenticates a user or supplies a grant.
func (s *Engine) oauthClientContext(ctx context.Context, client authflow.OAuthClient) (context.Context, error) {
	if client.TenantID.IsZero() {
		return ctx, nil
	}
	if selected, err := s.tenantID(ctx); err == nil && selected != client.TenantID {
		return nil, authflow.NewOAuthError(authflow.OAuthInvalidGrant, "the client belongs to another account directory")
	}
	return WithTenant(ctx, client.TenantID), nil
}

// Only an already signature-verified native token may route a personal OAuth
// request. Live account ownership is authoritative; a fixed mount stays fixed.
func (s *Engine) oauthAccountContext(ctx context.Context, claims map[string]any) (context.Context, error) {
	owner, err := s.credentialTenant(ctx, s.q, jose.String(claims, "sub"), jose.String(claims, "tenant_id"))
	if err != nil {
		return nil, err
	}
	if selected, err := s.tenantID(ctx); err == nil && selected != owner {
		return nil, iam.ErrTenantMismatch
	}
	return WithTenant(ctx, owner), nil
}
