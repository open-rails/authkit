package identity

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Rename history queries (e2e issue #58).
//
// Two operations are exposed:
//
//   ForwardTenantSlug      — given a historical slug, return the current
//                          slug of the tenant that holds it. Single-hop;
//                          rename rows always carry the immutable tenant_id
//                          so we never need to walk a chain.
//   ListTenantRenameHistory — historical rename rows ordered by renamed_at.
//                          The first row's from_slug is the first known
//                          historical slug, and the final row's to_slug is
//                          the current slug unless another rename has since
//                          been written.
//
// Same shape for users.
//
// See e2e/agents/progress.json issue #58 for the design + index choices.
// All queries hit covering indexes; sub-ms in steady state.

// ErrSlugNotFound is returned when neither the tenants/users table nor the
// rename history contains the requested slug.
var ErrSlugNotFound = errors.New("slug_not_found")

func (s *Store) tenantRenamesTable() string { return s.schema + ".tenant_renames" }
func (s *Store) userRenamesTable() string   { return s.schema + ".user_renames" }

// RenameHop is one entry in a row's rename history.
type RenameHop struct {
	FromSlug  string
	ToSlug    string
	RenamedAt time.Time
	RenamedBy string // empty when actor wasn't recorded (e.g. backfilled rows)
}

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
	var current string
	err := s.pg.QueryRow(ctx, `
		SELECT slug FROM `+s.tenantsTable()+`
		WHERE lower(slug) = $1 AND deleted_at IS NULL
		LIMIT 1
	`, slug).Scan(&current)
	if err == nil {
		return current, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	err = s.pg.QueryRow(ctx, `
		SELECT o.slug
		FROM `+s.tenantRenamesTable()+` r
		JOIN `+s.tenantsTable()+` o ON o.id = r.tenant_id AND o.deleted_at IS NULL
		WHERE r.from_slug = $1
		ORDER BY r.renamed_at DESC
		LIMIT 1
	`, slug).Scan(&current)
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
	var current string
	err := s.pg.QueryRow(ctx, `
		SELECT username FROM `+s.usersTable()+`
		WHERE username = $1 AND deleted_at IS NULL
		LIMIT 1
	`, username).Scan(&current)
	if err == nil {
		return current, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	err = s.pg.QueryRow(ctx, `
		SELECT u.username
		FROM `+s.userRenamesTable()+` r
		JOIN `+s.usersTable()+` u ON u.id = r.user_id AND u.deleted_at IS NULL
		WHERE r.from_slug = $1
		ORDER BY r.renamed_at DESC
		LIMIT 1
	`, username).Scan(&current)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrSlugNotFound
		}
		return "", err
	}
	return current, nil
}

// ListTenantRenameHistory returns the recorded tenant slug rename rows in
// chronological order. Tenants with no renames return an empty slice.
func (s *Store) ListTenantRenameHistory(ctx context.Context, tenantID string) ([]RenameHop, error) {
	tenantID = strings.TrimSpace(tenantID)
	if s.pg == nil || tenantID == "" {
		return nil, nil
	}
	rows, err := s.pg.Query(ctx, `
		SELECT from_slug, to_slug, renamed_at, COALESCE(renamed_by::text, '')
		FROM `+s.tenantRenamesTable()+`
		WHERE tenant_id = $1::uuid
		ORDER BY renamed_at ASC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RenameHop
	for rows.Next() {
		var h RenameHop
		if err := rows.Scan(&h.FromSlug, &h.ToSlug, &h.RenamedAt, &h.RenamedBy); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ListUserRenameHistory is the user equivalent. Users with no renames return
// an empty slice.
func (s *Store) ListUserRenameHistory(ctx context.Context, userID string) ([]RenameHop, error) {
	userID = strings.TrimSpace(userID)
	if s.pg == nil || userID == "" {
		return nil, nil
	}
	rows, err := s.pg.Query(ctx, `
		SELECT from_slug, to_slug, renamed_at, COALESCE(renamed_by::text, '')
		FROM `+s.userRenamesTable()+`
		WHERE user_id = $1::uuid
		ORDER BY renamed_at ASC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RenameHop
	for rows.Next() {
		var h RenameHop
		if err := rows.Scan(&h.FromSlug, &h.ToSlug, &h.RenamedAt, &h.RenamedBy); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
