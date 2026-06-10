package identity

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Rename-history forwarding (e2e issue #58).
//
//	ForwardTenantSlug — given a historical slug, return the current slug of
//	the tenant that holds it. Single-hop; rename rows always carry the
//	immutable tenant_id so we never need to walk a chain.
//
// Same shape for users (ForwardUserUsername).
//
// See e2e/agents/progress.json issue #58 for the design + index choices.
// All queries hit covering indexes; sub-ms in steady state.

// ErrSlugNotFound is returned when neither the tenants/users table nor the
// rename history contains the requested slug.
var ErrSlugNotFound = errors.New("slug_not_found")

// ForwardTenantSlug resolves any slug — current OR historical — to the
// current slug of the owning tenant. Returns ErrSlugNotFound when no row
// matches.
//
// Lookup order:
//  1. Direct match on tenants.slug (the typical "no rename" case).
//  2. Match on tenant_renames.from_slug, joined to live tenants row,
//     most-recent-rename wins (handles rename-back + post-hard-delete reuse).
func (s *Store) ForwardTenantSlug(ctx context.Context, slug string) (string, error) {
	slug = strings.ToLower(strings.TrimSpace(slug))
	if s.pg == nil || slug == "" {
		return "", ErrSlugNotFound
	}
	current, err := s.q.IdentityCurrentTenantSlug(ctx, slug)
	if err == nil {
		return current, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	current, err = s.q.IdentityForwardTenantSlug(ctx, slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrSlugNotFound
		}
		return "", err
	}
	return current, nil
}

// ForwardUserUsername is the user-namespace equivalent of ForwardTenantSlug.
func (s *Store) ForwardUserUsername(ctx context.Context, username string) (string, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if s.pg == nil || username == "" {
		return "", ErrSlugNotFound
	}
	current, err := s.q.IdentityCurrentUsername(ctx, &username)
	if err == nil {
		return deref(current), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	current, err = s.q.IdentityForwardUsername(ctx, username)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrSlugNotFound
		}
		return "", err
	}
	return deref(current), nil
}
