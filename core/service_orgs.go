package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrOrgNotFound      = errors.New("org_not_found")
	ErrNotOrgMember     = errors.New("not_org_member")
	ErrInvalidOrgSlug   = errors.New("invalid_org_slug")
	ErrInvalidOrgRole   = errors.New("invalid_org_role")
	ErrProtectedOrgRole = errors.New("protected_org_role")
	ErrLastOrgOwner     = errors.New("cannot_remove_last_owner")
)

// Org is a minimal org record.
type Org struct {
	ID   string
	Slug string
}

// OrgMembership is a user's membership with optional roles.
type OrgMembership struct {
	Org   string
	Roles []string
}

const (
	orgSlugMaxLen = 63
	orgRoleMaxLen = 64

	// These guardrails are hardcoded and intentionally not configurable.
	maxOrgsPerUser        = 200
	maxRolesPerMembership = 50

	// Reserved org role names.
	orgOwnerRole = "owner"
)

func validateOrgSlug(slug string) error {
	s := strings.TrimSpace(slug)
	if s == "" || len(s) > orgSlugMaxLen {
		return ErrInvalidOrgSlug
	}
	// Keep validation consistent with migration regex:
	// ^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$
	if s[0] == '-' || s[len(s)-1] == '-' {
		return ErrInvalidOrgSlug
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= '0' && ch <= '9':
		case ch == '-':
		default:
			return ErrInvalidOrgSlug
		}
	}
	return nil
}

func validateOrgRole(role string) error {
	r := strings.TrimSpace(role)
	if r == "" || len(r) > orgRoleMaxLen {
		return ErrInvalidOrgRole
	}
	for i := 0; i < len(r); i++ {
		ch := r[i]
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == '_' || ch == '-' || ch == ':':
		default:
			return ErrInvalidOrgRole
		}
	}
	return nil
}

func canonicalizeOrgRole(role string) string {
	r := strings.TrimSpace(role)
	if strings.EqualFold(r, orgOwnerRole) {
		return orgOwnerRole
	}
	return r
}

func (s *Service) requirePG() error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	return nil
}

// ResolveOrgBySlug resolves an org by current slug or alias.
// Returns ErrOrgNotFound when no org matches.
func (s *Service) ResolveOrgBySlug(ctx context.Context, slug string) (*Org, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if err := validateOrgSlug(slug); err != nil {
		return nil, err
	}
	var id, canonical string
	// Prefer current slug.
	err := s.pg.QueryRow(ctx, `SELECT id::text, slug FROM profiles.orgs WHERE slug=$1 AND deleted_at IS NULL`, slug).Scan(&id, &canonical)
	if err == nil {
		return &Org{ID: id, Slug: canonical}, nil
	}
	// Fallback to alias.
	err = s.pg.QueryRow(ctx, `
		SELECT o.id::text, o.slug
		FROM profiles.org_slug_aliases a
		JOIN profiles.orgs o ON o.id=a.org_id
		WHERE a.slug=$1 AND a.deleted_at IS NULL AND o.deleted_at IS NULL
	`, slug).Scan(&id, &canonical)
	if err != nil {
		return nil, ErrOrgNotFound
	}
	return &Org{ID: id, Slug: canonical}, nil
}

func (s *Service) CreateOrg(ctx context.Context, slug string) (*Org, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	slug = strings.TrimSpace(slug)
	if err := validateOrgSlug(slug); err != nil {
		return nil, err
	}
	var id, canonical string
	err := s.pg.QueryRow(ctx, `
		INSERT INTO profiles.orgs (slug)
		VALUES ($1)
		RETURNING id::text, slug
	`, slug).Scan(&id, &canonical)
	if err != nil {
		return nil, err
	}
	// Ensure the reserved owner role always exists for every org.
	if _, err := s.pg.Exec(ctx, `
		INSERT INTO profiles.org_roles (org_id, role)
		VALUES ($1::uuid, $2)
		ON CONFLICT (org_id, role) DO NOTHING
	`, id, orgOwnerRole); err != nil {
		return nil, err
	}
	return &Org{ID: id, Slug: canonical}, nil
}

func (s *Service) RenameOrgSlug(ctx context.Context, orgID, newSlug string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	newSlug = strings.TrimSpace(newSlug)
	if err := validateOrgSlug(newSlug); err != nil {
		return err
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var oldSlug string
	if err := tx.QueryRow(ctx, `SELECT slug FROM profiles.orgs WHERE id=$1::uuid AND deleted_at IS NULL`, orgID).Scan(&oldSlug); err != nil {
		return ErrOrgNotFound
	}
	if strings.EqualFold(oldSlug, newSlug) {
		return nil
	}
	// Insert old slug as alias (idempotent-ish).
	_, _ = tx.Exec(ctx, `
		INSERT INTO profiles.org_slug_aliases (org_id, slug)
		VALUES ($1::uuid, $2)
		ON CONFLICT (org_id, slug) DO UPDATE SET deleted_at=NULL
	`, orgID, oldSlug)

	if _, err := tx.Exec(ctx, `UPDATE profiles.orgs SET slug=$1, updated_at=now() WHERE id=$2::uuid AND deleted_at IS NULL`, newSlug, orgID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) ListOrgMembershipsForUser(ctx context.Context, userID string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("invalid_user")
	}
	rows, err := s.pg.Query(ctx, `
		SELECT o.slug
		FROM profiles.org_members m
		JOIN profiles.orgs o ON o.id=m.org_id
		WHERE m.user_id=$1::uuid AND m.deleted_at IS NULL AND o.deleted_at IS NULL
		ORDER BY o.slug ASC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var slug string
		if err := rows.Scan(&slug); err != nil {
			return nil, err
		}
		out = append(out, slug)
		if len(out) > maxOrgsPerUser {
			return nil, fmt.Errorf("org_membership_limit_exceeded")
		}
	}
	return out, rows.Err()
}

func (s *Service) ListUserOrgMembershipsAndRoles(ctx context.Context, userID string) ([]OrgMembership, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	orgs, err := s.ListOrgMembershipsForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]OrgMembership, 0, len(orgs))
	for _, orgSlug := range orgs {
		roles, err := s.ReadMemberRoles(ctx, orgSlug, userID)
		if err != nil {
			return nil, err
		}
		out = append(out, OrgMembership{Org: orgSlug, Roles: roles})
	}
	return out, nil
}

func (s *Service) AddMember(ctx context.Context, orgSlug, userID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return err
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invalid_user")
	}
	// Guardrail.
	if orgs, e := s.ListOrgMembershipsForUser(ctx, userID); e == nil && len(orgs) >= maxOrgsPerUser {
		return fmt.Errorf("org_membership_limit_exceeded")
	}
	_, err = s.pg.Exec(ctx, `
		INSERT INTO profiles.org_members (org_id, user_id)
		VALUES ($1::uuid, $2::uuid)
		ON CONFLICT (org_id, user_id) DO UPDATE SET deleted_at=NULL, updated_at=now()
	`, org.ID, userID)
	return err
}

func (s *Service) RemoveMember(ctx context.Context, orgSlug, userID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return err
	}
	// Prevent removing the last owner from the org.
	var isOwner bool
	if err := s.pg.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM profiles.org_member_roles r
			JOIN profiles.org_members m ON m.org_id=r.org_id AND m.user_id=r.user_id
			WHERE r.org_id=$1::uuid AND r.user_id=$2::uuid AND r.role=$3 AND m.deleted_at IS NULL
		)
	`, org.ID, userID, orgOwnerRole).Scan(&isOwner); err != nil {
		return err
	}
	if isOwner {
		var ownerCount int
		if err := s.pg.QueryRow(ctx, `
			SELECT COUNT(*)
			FROM profiles.org_member_roles r
			JOIN profiles.org_members m ON m.org_id=r.org_id AND m.user_id=r.user_id
			WHERE r.org_id=$1::uuid AND r.role=$2 AND m.deleted_at IS NULL
		`, org.ID, orgOwnerRole).Scan(&ownerCount); err != nil {
			return err
		}
		if ownerCount <= 1 {
			return ErrLastOrgOwner
		}
	}
	_, err = s.pg.Exec(ctx, `UPDATE profiles.org_members SET deleted_at=now(), updated_at=now() WHERE org_id=$1::uuid AND user_id=$2::uuid AND deleted_at IS NULL`, org.ID, userID)
	return err
}

func (s *Service) DefineRole(ctx context.Context, orgSlug, role string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return err
	}
	role = canonicalizeOrgRole(role)
	if err := validateOrgRole(role); err != nil {
		return err
	}
	_, err = s.pg.Exec(ctx, `INSERT INTO profiles.org_roles (org_id, role) VALUES ($1::uuid,$2) ON CONFLICT (org_id, role) DO NOTHING`, org.ID, role)
	return err
}

func (s *Service) DeleteRole(ctx context.Context, orgSlug, role string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return err
	}
	role = canonicalizeOrgRole(role)
	if err := validateOrgRole(role); err != nil {
		return err
	}
	if role == orgOwnerRole {
		return ErrProtectedOrgRole
	}
	_, err = s.pg.Exec(ctx, `DELETE FROM profiles.org_roles WHERE org_id=$1::uuid AND role=$2`, org.ID, role)
	return err
}

func (s *Service) AssignRole(ctx context.Context, orgSlug, userID, role string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return err
	}
	role = canonicalizeOrgRole(role)
	if err := validateOrgRole(role); err != nil {
		return err
	}
	// Guardrail.
	roles, err := s.ReadMemberRoles(ctx, orgSlug, userID)
	if err == nil && len(roles) >= maxRolesPerMembership {
		return fmt.Errorf("org_role_limit_exceeded")
	}
	_, err = s.pg.Exec(ctx, `
		INSERT INTO profiles.org_member_roles (org_id, user_id, role)
		SELECT $1::uuid, $2::uuid, $3
		WHERE EXISTS (SELECT 1 FROM profiles.org_members WHERE org_id=$1::uuid AND user_id=$2::uuid AND deleted_at IS NULL)
		  AND EXISTS (SELECT 1 FROM profiles.org_roles WHERE org_id=$1::uuid AND role=$3)
		ON CONFLICT (org_id, user_id, role) DO NOTHING
	`, org.ID, userID, role)
	return err
}

func (s *Service) UnassignRole(ctx context.Context, orgSlug, userID, role string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return err
	}
	role = canonicalizeOrgRole(role)
	if err := validateOrgRole(role); err != nil {
		return err
	}
	if role == orgOwnerRole {
		var ownerCount int
		if err := s.pg.QueryRow(ctx, `
			SELECT COUNT(*)
			FROM profiles.org_member_roles r
			JOIN profiles.org_members m ON m.org_id=r.org_id AND m.user_id=r.user_id
			WHERE r.org_id=$1::uuid AND r.role=$2 AND m.deleted_at IS NULL
		`, org.ID, orgOwnerRole).Scan(&ownerCount); err != nil {
			return err
		}
		if ownerCount <= 1 {
			return ErrLastOrgOwner
		}
	}
	_, err = s.pg.Exec(ctx, `DELETE FROM profiles.org_member_roles WHERE org_id=$1::uuid AND user_id=$2::uuid AND role=$3`, org.ID, userID, role)
	return err
}

func (s *Service) ReadMemberRoles(ctx context.Context, orgSlug, userID string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return nil, err
	}
	rows, err := s.pg.Query(ctx, `
		SELECT r.role
		FROM profiles.org_member_roles r
		WHERE r.org_id=$1::uuid AND r.user_id=$2::uuid
		ORDER BY r.role ASC
	`, org.ID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		out = append(out, role)
		if len(out) > maxRolesPerMembership {
			return nil, fmt.Errorf("org_role_limit_exceeded")
		}
	}
	return out, rows.Err()
}

func (s *Service) IsOrgMember(ctx context.Context, orgSlug, userID string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return false, err
	}
	var ok bool
	if err := s.pg.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM profiles.org_members WHERE org_id=$1::uuid AND user_id=$2::uuid AND deleted_at IS NULL)`, org.ID, userID).Scan(&ok); err != nil {
		return false, err
	}
	return ok, nil
}

func (s *Service) ListOrgMembers(ctx context.Context, orgSlug string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return nil, err
	}
	rows, err := s.pg.Query(ctx, `
		SELECT user_id::text
		FROM profiles.org_members
		WHERE org_id=$1::uuid AND deleted_at IS NULL
		ORDER BY user_id::text ASC
	`, org.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *Service) ListOrgDefinedRoles(ctx context.Context, orgSlug string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return nil, err
	}
	rows, err := s.pg.Query(ctx, `
		SELECT role
		FROM profiles.org_roles
		WHERE org_id=$1::uuid
		ORDER BY role ASC
	`, org.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	return out, rows.Err()
}
