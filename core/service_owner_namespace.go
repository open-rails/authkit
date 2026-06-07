package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrOwnerSlugTaken       = errors.New("owner_slug_taken")
	ErrPersonalTenantLocked = errors.New("personal_tenant_locked")
	ErrInviteNotFound       = errors.New("tenant_invite_not_found")
	ErrInviteNotPending     = errors.New("tenant_invite_not_pending")
	ErrInviteNotForUser     = errors.New("tenant_invite_not_for_user")
	ErrInviteExpired        = errors.New("tenant_invite_expired")
	ErrPersonalOrgNotFound  = errors.New("personal_tenant_not_found")
)

func ownerSlugFromUsername(username string) string {
	s := strings.ToLower(strings.TrimSpace(username))
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	prevDash := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z':
			b.WriteByte(ch)
			prevDash = false
		case ch >= '0' && ch <= '9':
			b.WriteByte(ch)
			prevDash = false
		case ch == '-' || ch == '_':
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	return out
}

func (s *Service) ownerSlugAvailable(ctx context.Context, slug, excludeUserID, excludeOrgID string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	slug = strings.ToLower(strings.TrimSpace(slug))
	if err := validateTenantSlug(slug); err != nil {
		return false, err
	}
	reuseCutoff := time.Now().UTC().Add(-renameReuseHold)
	var exists bool
	if err := s.pg.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM profiles.owner_reserved_names r
			WHERE r.slug=$1
		)
	`, slug).Scan(&exists); err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	if err := s.pg.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM profiles.users u
			WHERE u.username=$1
			  AND ($2::text = '' OR u.id::text <> $2::text)
		)
	`, slug, strings.TrimSpace(excludeUserID)).Scan(&exists); err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	// Squat protection from recent rename history. A historical `from_slug`
	// blocks reuse by anyone except the row that owned it until
	// renameReuseHold expires. Same-row reclaim is allowed via the exclude
	// parameters. Joins to owner rows without filtering soft deletes: soft
	// deletion keeps the namespace held, while hard deletion removes/cascades
	// the owner row and allows eventual reuse.
	if err := s.pg.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM profiles.user_renames r
			JOIN profiles.users u ON u.id=r.user_id
			WHERE r.from_slug=$1
			  AND r.renamed_at >= $3
			  AND ($2::text = '' OR r.user_id::text <> $2::text)
		)
	`, slug, strings.TrimSpace(excludeUserID), reuseCutoff).Scan(&exists); err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	if err := s.pg.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM profiles.tenants o
			WHERE o.slug=$1
			  AND ($2::text = '' OR o.id::text <> $2::text)
		)
	`, slug, strings.TrimSpace(excludeOrgID)).Scan(&exists); err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	if err := s.pg.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM profiles.tenant_renames r
			JOIN profiles.tenants o ON o.id=r.tenant_id
			WHERE r.from_slug=$1
			  AND r.renamed_at >= $3
			  AND ($2::text = '' OR r.tenant_id::text <> $2::text)
		)
	`, slug, strings.TrimSpace(excludeOrgID), reuseCutoff).Scan(&exists); err != nil {
		return false, err
	}
	return !exists, nil
}

func (s *Service) ensureOwnerSlugAvailable(ctx context.Context, slug, excludeUserID, excludeOrgID string) error {
	ok, err := s.ownerSlugAvailable(ctx, slug, excludeUserID, excludeOrgID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrOwnerSlugTaken
	}
	return nil
}

func (s *Service) GetPersonalOrgForUser(ctx context.Context, userID string) (*Tenant, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("invalid_user")
	}
	var out Tenant
	if err := s.pg.QueryRow(ctx, `
		SELECT id::text, slug, is_personal, COALESCE(owner_user_id::text,'')
		FROM profiles.tenants
		WHERE owner_user_id=$1::uuid AND is_personal=true AND deleted_at IS NULL
	`, userID).Scan(&out.ID, &out.Slug, &out.IsPersonal, &out.OwnerUserID); err != nil {
		return nil, ErrPersonalOrgNotFound
	}
	return &out, nil
}

// ListUserSlugAliases returns every historical username this user has
// held (excluding the current one). Source: `user_renames.from_slug`
// (issue #58). Distinct values; order by usage timeline.
func (s *Service) ListUserSlugAliases(ctx context.Context, userID string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("invalid_user")
	}
	rows, err := s.pg.Query(ctx, `
		SELECT DISTINCT from_slug
		FROM profiles.user_renames
		WHERE user_id=$1::uuid
		ORDER BY from_slug ASC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]string, 0, 4)
	for rows.Next() {
		var slug string
		if err := rows.Scan(&slug); err != nil {
			return nil, err
		}
		out = append(out, slug)
	}
	return out, rows.Err()
}

func (s *Service) ResolveUserBySlug(ctx context.Context, slug string) (userID string, username string, err error) {
	if err := s.requirePG(); err != nil {
		return "", "", err
	}
	slug = strings.TrimSpace(slug)
	if slug == "" {
		return "", "", fmt.Errorf("invalid_slug")
	}
	slug = strings.ToLower(slug)
	if err := s.pg.QueryRow(ctx, `
		SELECT id::text, username::text
		FROM profiles.users
		WHERE username=$1 AND deleted_at IS NULL
	`, slug).Scan(&userID, &username); err == nil {
		return userID, username, nil
	}
	// Fallback to renames table (issue #58). Most-recent rename wins
	// when a slug has been used by multiple users at different times
	// (only possible after hard-delete + reuse).
	if err := s.pg.QueryRow(ctx, `
		SELECT u.id::text, u.username::text
		FROM profiles.user_renames r
		JOIN profiles.users u ON u.id=r.user_id AND u.deleted_at IS NULL
		WHERE r.from_slug=$1
		ORDER BY r.renamed_at DESC
		LIMIT 1
	`, slug).Scan(&userID, &username); err != nil {
		return "", "", ErrUserNotFound
	}
	return userID, username, nil
}

// ListOrgAliases returns every historical slug this tenant has held
// (excluding the current one). Source: `tenant_renames.from_slug` (issue
// #58). Distinct values.
func (s *Service) ListOrgAliases(ctx context.Context, tenantID string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(tenantID) == "" {
		return nil, fmt.Errorf("invalid_org")
	}
	rows, err := s.pg.Query(ctx, `
		SELECT DISTINCT from_slug
		FROM profiles.tenant_renames
		WHERE tenant_id=$1::uuid
		ORDER BY from_slug ASC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]string, 0, 4)
	for rows.Next() {
		var slug string
		if err := rows.Scan(&slug); err != nil {
			return nil, err
		}
		out = append(out, slug)
	}
	return out, rows.Err()
}

func (s *Service) ensurePersonalOrgForUser(ctx context.Context, userID, username string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	// (issue 60) Gated by AutoCreatePersonalTenantsEnabled at every call site; no
	// tenant-mode check here.
	userID = strings.TrimSpace(userID)
	slug := ownerSlugFromUsername(username)
	if userID == "" || slug == "" {
		return fmt.Errorf("invalid_personal_org")
	}
	if err := validateTenantSlug(slug); err != nil {
		return err
	}
	if err := s.ensureOwnerSlugAvailable(ctx, slug, userID, ""); err != nil {
		return err
	}

	tenantIDToInsert, err := newUUIDV7String()
	if err != nil {
		return err
	}
	var tenantID string
	err = s.pg.QueryRow(ctx, `
		INSERT INTO profiles.tenants (id, slug, is_personal, owner_user_id, metadata)
		VALUES ($1::uuid, $2, true, $3::uuid, jsonb_build_object('namespace_state', 'registered_tenant', 'reserved', to_jsonb(false)))
		ON CONFLICT (owner_user_id) WHERE is_personal=true AND deleted_at IS NULL
		DO UPDATE SET slug=EXCLUDED.slug, updated_at=now()
		RETURNING id::text
	`, tenantIDToInsert, slug, userID).Scan(&tenantID)
	if err != nil {
		return err
	}

	if _, err := s.pg.Exec(ctx, `
		INSERT INTO profiles.tenant_roles (tenant_id, role)
		VALUES ($1::uuid, 'owner'), ($1::uuid, 'member')
		ON CONFLICT (tenant_id, role) DO NOTHING
	`, tenantID); err != nil {
		return err
	}
	if _, err := s.pg.Exec(ctx, `
		INSERT INTO profiles.tenant_memberships (tenant_id, user_id, role)
		VALUES ($1::uuid, $2::uuid, 'owner')
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET role='owner', deleted_at=NULL, updated_at=now()
	`, tenantID, userID); err != nil {
		return err
	}
	// Seed owner=`*` + any app-declared default roles for the personal tenant.
	if err := s.seedRolePermissionDefaults(ctx, tenantID); err != nil {
		return err
	}
	return nil
}
