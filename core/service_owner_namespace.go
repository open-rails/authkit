package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrOwnerSlugTaken      = errors.New("owner_slug_taken")
	ErrPersonalOrgLocked   = errors.New("personal_org_locked")
	ErrInviteNotFound      = errors.New("org_invite_not_found")
	ErrInviteNotPending    = errors.New("org_invite_not_pending")
	ErrInviteNotForUser    = errors.New("org_invite_not_for_user")
	ErrInviteExpired       = errors.New("org_invite_expired")
	ErrPersonalOrgNotFound = errors.New("personal_org_not_found")
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
	if err := validateOrgSlug(slug); err != nil {
		return false, err
	}
	var exists bool
	if err := s.pg.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM profiles.users u
			WHERE lower(u.username::text)=lower($1)
			  AND u.deleted_at IS NULL
			  AND ($2::text = '' OR u.id::text <> $2::text)
		)
	`, slug, strings.TrimSpace(excludeUserID)).Scan(&exists); err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	if err := s.pg.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM profiles.user_slug_aliases a
			WHERE lower(a.slug::text)=lower($1)
			  AND a.deleted_at IS NULL
			  AND ($2::text = '' OR a.user_id::text <> $2::text)
		)
	`, slug, strings.TrimSpace(excludeUserID)).Scan(&exists); err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	if err := s.pg.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM profiles.orgs o
			WHERE o.slug=$1
			  AND o.deleted_at IS NULL
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
			FROM profiles.org_slug_aliases a
			WHERE a.slug=$1
			  AND a.deleted_at IS NULL
			  AND ($2::text = '' OR a.org_id::text <> $2::text)
		)
	`, slug, strings.TrimSpace(excludeOrgID)).Scan(&exists); err != nil {
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

func (s *Service) GetPersonalOrgForUser(ctx context.Context, userID string) (*Org, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("invalid_user")
	}
	var out Org
	if err := s.pg.QueryRow(ctx, `
		SELECT id::text, slug, is_personal, COALESCE(owner_user_id::text,'')
		FROM profiles.orgs
		WHERE owner_user_id=$1::uuid AND is_personal=true AND deleted_at IS NULL
	`, userID).Scan(&out.ID, &out.Slug, &out.IsPersonal, &out.OwnerUserID); err != nil {
		return nil, ErrPersonalOrgNotFound
	}
	return &out, nil
}

func (s *Service) ListUserSlugAliases(ctx context.Context, userID string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("invalid_user")
	}
	rows, err := s.pg.Query(ctx, `
		SELECT slug::text
		FROM profiles.user_slug_aliases
		WHERE user_id=$1::uuid AND deleted_at IS NULL
		ORDER BY slug::text ASC
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
	if err := s.pg.QueryRow(ctx, `
		SELECT id::text, username::text
		FROM profiles.users
		WHERE lower(username::text)=lower($1) AND deleted_at IS NULL
	`, slug).Scan(&userID, &username); err == nil {
		return userID, username, nil
	}
	if err := s.pg.QueryRow(ctx, `
		SELECT u.id::text, u.username::text
		FROM profiles.user_slug_aliases a
		JOIN profiles.users u ON u.id=a.user_id
		WHERE lower(a.slug::text)=lower($1)
		  AND a.deleted_at IS NULL
		  AND u.deleted_at IS NULL
	`, slug).Scan(&userID, &username); err != nil {
		return "", "", ErrUserNotFound
	}
	return userID, username, nil
}

func (s *Service) ListOrgAliases(ctx context.Context, orgID string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(orgID) == "" {
		return nil, fmt.Errorf("invalid_org")
	}
	rows, err := s.pg.Query(ctx, `
		SELECT slug
		FROM profiles.org_slug_aliases
		WHERE org_id=$1::uuid AND deleted_at IS NULL
		ORDER BY slug ASC
	`, orgID)
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
	if !strings.EqualFold(strings.TrimSpace(s.opts.OrgMode), "multi") {
		return nil
	}
	userID = strings.TrimSpace(userID)
	slug := ownerSlugFromUsername(username)
	if userID == "" || slug == "" {
		return fmt.Errorf("invalid_personal_org")
	}
	if err := validateOrgSlug(slug); err != nil {
		return err
	}
	if err := s.ensureOwnerSlugAvailable(ctx, slug, userID, ""); err != nil {
		return err
	}

	var orgID string
	err := s.pg.QueryRow(ctx, `
		INSERT INTO profiles.orgs (slug, is_personal, owner_user_id)
		VALUES ($1, true, $2::uuid)
		ON CONFLICT (owner_user_id) WHERE is_personal=true AND deleted_at IS NULL
		DO UPDATE SET slug=EXCLUDED.slug, updated_at=now()
		RETURNING id::text
	`, slug, userID).Scan(&orgID)
	if err != nil {
		return err
	}

	if _, err := s.pg.Exec(ctx, `
		INSERT INTO profiles.org_roles (org_id, role)
		VALUES ($1::uuid, 'owner'), ($1::uuid, 'member')
		ON CONFLICT (org_id, role) DO NOTHING
	`, orgID); err != nil {
		return err
	}
	if _, err := s.pg.Exec(ctx, `
		INSERT INTO profiles.org_members (org_id, user_id)
		VALUES ($1::uuid, $2::uuid)
		ON CONFLICT (org_id, user_id) DO UPDATE SET deleted_at=NULL, updated_at=now()
	`, orgID, userID); err != nil {
		return err
	}
	if _, err := s.pg.Exec(ctx, `
		INSERT INTO profiles.org_member_roles (org_id, user_id, role)
		VALUES ($1::uuid, $2::uuid, 'owner')
		ON CONFLICT (org_id, user_id, role) DO NOTHING
	`, orgID, userID); err != nil {
		return err
	}
	return nil
}
