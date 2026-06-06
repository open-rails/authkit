package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrTenantNotFound      = errors.New("tenant_not_found")
	ErrNotTenantMember     = errors.New("not_tenant_member")
	ErrInvalidTenantSlug   = errors.New("invalid_tenant_slug")
	ErrInvalidTenantRole   = errors.New("invalid_tenant_role")
	ErrProtectedTenantRole = errors.New("protected_tenant_role")
	ErrLastTenantOwner     = errors.New("cannot_remove_last_owner")
	ErrPersonalTenantOwner = errors.New("cannot_remove_personal_tenant_owner")
	// ErrRenameRateLimited is returned when a rename attempt happens
	// within renameCooldown of the previous rename for the same row.
	// Admin override paths (RenameTenantSlugForce / RenameUsernameForce)
	// bypass the check.
	ErrRenameRateLimited = errors.New("rename_rate_limited")
)

// Tenant is a minimal tenant record.
type Tenant struct {
	ID          string
	Slug        string
	IsPersonal  bool
	OwnerUserID string
}

// TenantMembership is a user's membership with optional roles.
type TenantMembership struct {
	Tenant string
	Roles  []string
}

const (
	tenantSlugMaxLen = 63
	tenantRoleMaxLen = 64

	// These guardrails are hardcoded and intentionally not configurable.
	maxOrgsPerUser = 200

	// Reserved tenant role names. `owner` is the ONLY role authkit hardcodes — it is
	// the tenant's root authority (seeded at creation, undeletable). Every other
	// role, including any `admin` role, is defined by the platform/app, not here.
	tenantOwnerRole = "owner"
)

func validateTenantSlug(slug string) error {
	s := strings.TrimSpace(slug)
	if s == "" || len(s) > tenantSlugMaxLen {
		return ErrInvalidTenantSlug
	}
	// Keep validation consistent with migration regex:
	// ^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$
	if s[0] == '-' || s[len(s)-1] == '-' {
		return ErrInvalidTenantSlug
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= '0' && ch <= '9':
		case ch == '-':
		default:
			return ErrInvalidTenantSlug
		}
	}
	return nil
}

func validateTenantRole(role string) error {
	r := strings.TrimSpace(role)
	if r == "" || len(r) > tenantRoleMaxLen {
		return ErrInvalidTenantRole
	}
	for i := 0; i < len(r); i++ {
		ch := r[i]
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == '_' || ch == '-' || ch == ':':
		default:
			return ErrInvalidTenantRole
		}
	}
	return nil
}

func canonicalizeTenantRole(role string) string {
	r := strings.TrimSpace(role)
	if strings.EqualFold(r, tenantOwnerRole) {
		return tenantOwnerRole
	}
	return r
}

func (s *Service) requirePG() error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	return nil
}

// ResolveTenantBySlug resolves an tenant by current slug or alias.
// Returns ErrTenantNotFound when no tenant matches.
func (s *Service) ResolveTenantBySlug(ctx context.Context, slug string) (*Tenant, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	slug = strings.ToLower(strings.TrimSpace(slug))
	if err := validateTenantSlug(slug); err != nil {
		return nil, err
	}
	var id, canonical string
	var isPersonal bool
	var ownerUserID string
	// Prefer current slug.
	err := s.pg.QueryRow(ctx, `
		SELECT id::text, slug, is_personal, COALESCE(owner_user_id::text, '')
		FROM profiles.tenants
		WHERE slug=$1 AND deleted_at IS NULL
	`, slug).Scan(&id, &canonical, &isPersonal, &ownerUserID)
	if err == nil {
		return &Tenant{ID: id, Slug: canonical, IsPersonal: isPersonal, OwnerUserID: ownerUserID}, nil
	}
	// Fallback to renames table (issue #58). The tenant_renames row's
	// `tenant_id` always points at the live owner — every rename row of
	// the same tenant carries the same UUID — so any historical slug
	// resolves to the tenant currently holding it. Take the most recent
	// row to handle the rare case where two different tenants have used
	// this slug at different times (e.g. after hard-delete + reuse).
	err = s.pg.QueryRow(ctx, `
		SELECT o.id::text, o.slug, o.is_personal, COALESCE(o.owner_user_id::text, '')
		FROM profiles.tenant_renames r
		JOIN profiles.tenants o ON o.id=r.tenant_id AND o.deleted_at IS NULL
		WHERE r.from_slug=$1
		ORDER BY r.renamed_at DESC
		LIMIT 1
	`, slug).Scan(&id, &canonical, &isPersonal, &ownerUserID)
	if err != nil {
		return nil, ErrTenantNotFound
	}
	return &Tenant{ID: id, Slug: canonical, IsPersonal: isPersonal, OwnerUserID: ownerUserID}, nil
}

func (s *Service) CreateTenant(ctx context.Context, slug string) (*Tenant, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	slug = strings.ToLower(strings.TrimSpace(slug))
	if err := validateTenantSlug(slug); err != nil {
		return nil, err
	}
	if err := s.ensureOwnerSlugAvailable(ctx, slug, "", ""); err != nil {
		return nil, err
	}
	tenantID, err := newUUIDV7String()
	if err != nil {
		return nil, err
	}
	var id, canonical string
	err = s.pg.QueryRow(ctx, `
		INSERT INTO profiles.tenants (id, slug, metadata)
		VALUES ($1::uuid, $2, jsonb_build_object('namespace_state', 'registered_tenant', 'reserved', to_jsonb(false)))
		RETURNING id::text, slug
	`, tenantID, slug).Scan(&id, &canonical)
	if err != nil {
		return nil, err
	}
	// Ensure the reserved owner role always exists for every tenant.
	if _, err := s.pg.Exec(ctx, `
		INSERT INTO profiles.tenant_roles (tenant_id, role)
		VALUES ($1::uuid, $2)
		ON CONFLICT (tenant_id, role) DO NOTHING
	`, id, tenantOwnerRole); err != nil {
		return nil, err
	}
	// Seed owner=`*` + any app-declared default roles (e.g. admin).
	if err := s.seedRolePermissionDefaults(ctx, id); err != nil {
		return nil, err
	}
	return &Tenant{ID: id, Slug: canonical}, nil
}

// RenameTenantSlug renames a non-personal tenant. Subject to the 72h
// `renameCooldown`. Personal tenants are renamed implicitly by the user-
// rename flow (see service.go) and reject this entrypoint with
// `ErrPersonalTenantLocked`.
//
// `actorUserID` is recorded on the rename audit row. Pass empty string
// when the caller doesn't have an authenticated user (e.g. internal
// admin tooling without an actor); the column is nullable.
func (s *Service) RenameTenantSlug(ctx context.Context, tenantID, newSlug, actorUserID string) error {
	return s.renameTenantSlugImpl(ctx, tenantID, newSlug, actorUserID, false)
}

// RenameTenantSlugForce is the admin-override variant that skips the 72h
// cooldown check. Otherwise identical to RenameTenantSlug. Caller is
// responsible for gating this behind admin scope upstream.
func (s *Service) RenameTenantSlugForce(ctx context.Context, tenantID, newSlug, actorUserID string) error {
	return s.renameTenantSlugImpl(ctx, tenantID, newSlug, actorUserID, true)
}

func (s *Service) renameTenantSlugImpl(ctx context.Context, tenantID, newSlug, actorUserID string, bypassCooldown bool) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	newSlug = strings.TrimSpace(newSlug)
	if err := validateTenantSlug(newSlug); err != nil {
		return err
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var oldSlug string
	var isPersonal bool
	if err := tx.QueryRow(ctx, `SELECT slug, is_personal FROM profiles.tenants WHERE id=$1::uuid AND deleted_at IS NULL`, tenantID).Scan(&oldSlug, &isPersonal); err != nil {
		return ErrTenantNotFound
	}
	if isPersonal {
		return ErrPersonalTenantLocked
	}
	if strings.EqualFold(oldSlug, newSlug) {
		return nil
	}

	// Cooldown check (issue #58). Walks the (tenant_id, renamed_at DESC)
	// index to grab the most recent rename for this tenant and rejects if
	// it's within the renameCooldown window.
	if !bypassCooldown {
		var lastRenamedAt *time.Time
		if err := tx.QueryRow(ctx, `
			SELECT renamed_at
			FROM   profiles.tenant_renames
			WHERE  tenant_id = $1::uuid
			ORDER  BY renamed_at DESC
			LIMIT  1
		`, tenantID).Scan(&lastRenamedAt); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if lastRenamedAt != nil && time.Since(*lastRenamedAt) < renameCooldown {
			return ErrRenameRateLimited
		}
	}

	if err := s.ensureOwnerSlugAvailable(ctx, newSlug, "", tenantID); err != nil {
		return err
	}

	// Audit row in tenant_renames. Source of truth for both forwarding
	// (from_slug → current owner) and reverse history (tenant_id → all
	// historical slugs in order).
	if _, err := tx.Exec(ctx, `
		INSERT INTO profiles.tenant_renames (tenant_id, from_slug)
		VALUES ($1::uuid, $2)
	`, tenantID, strings.ToLower(strings.TrimSpace(oldSlug))); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `UPDATE profiles.tenants SET slug=$1, updated_at=now() WHERE id=$2::uuid AND deleted_at IS NULL`, newSlug, tenantID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) ListTenantMembershipsForUser(ctx context.Context, userID string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("invalid_user")
	}
	rows, err := s.pg.Query(ctx, `
		SELECT o.slug
		FROM profiles.tenant_memberships m
		JOIN profiles.tenants o ON o.id=m.tenant_id
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
			return nil, fmt.Errorf("tenant_membership_limit_exceeded")
		}
	}
	return out, rows.Err()
}

func (s *Service) ListUserTenantMembershipsAndRoles(ctx context.Context, userID string) ([]TenantMembership, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	tenants, err := s.ListTenantMembershipsForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]TenantMembership, 0, len(tenants))
	for _, tenantSlug := range tenants {
		roles, err := s.ReadMemberRoles(ctx, tenantSlug, userID)
		if err != nil {
			return nil, err
		}
		out = append(out, TenantMembership{Tenant: tenantSlug, Roles: roles})
	}
	return out, nil
}

func (s *Service) AddMember(ctx context.Context, tenantSlug, userID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return err
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invalid_user")
	}
	// Guardrail.
	if tenants, e := s.ListTenantMembershipsForUser(ctx, userID); e == nil && len(tenants) >= maxOrgsPerUser {
		return fmt.Errorf("tenant_membership_limit_exceeded")
	}
	_, err = s.pg.Exec(ctx, `
		INSERT INTO profiles.tenant_memberships (tenant_id, user_id, role)
		VALUES ($1::uuid, $2::uuid, 'member')
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET deleted_at=NULL, updated_at=now()
	`, tenant.ID, userID)
	return err
}

func (s *Service) RemoveMember(ctx context.Context, tenantSlug, userID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return err
	}
	if tenant.IsPersonal && strings.EqualFold(strings.TrimSpace(tenant.OwnerUserID), strings.TrimSpace(userID)) {
		return ErrPersonalTenantOwner
	}
	// Prevent removing the last owner from the tenant.
	var isOwner bool
	if err := s.pg.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM profiles.tenant_memberships
			WHERE tenant_id=$1::uuid AND user_id=$2::uuid AND role=$3 AND deleted_at IS NULL
		)
	`, tenant.ID, userID, tenantOwnerRole).Scan(&isOwner); err != nil {
		return err
	}
	if isOwner {
		var ownerCount int
		if err := s.pg.QueryRow(ctx, `
			SELECT COUNT(*)
			FROM profiles.tenant_memberships
			WHERE tenant_id=$1::uuid AND role=$2 AND deleted_at IS NULL
		`, tenant.ID, tenantOwnerRole).Scan(&ownerCount); err != nil {
			return err
		}
		if ownerCount <= 1 {
			return ErrLastTenantOwner
		}
	}
	_, err = s.pg.Exec(ctx, `UPDATE profiles.tenant_memberships SET deleted_at=now(), updated_at=now() WHERE tenant_id=$1::uuid AND user_id=$2::uuid AND deleted_at IS NULL`, tenant.ID, userID)
	return err
}

func (s *Service) DefineRole(ctx context.Context, tenantSlug, role string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return err
	}
	role = canonicalizeTenantRole(role)
	if err := validateTenantRole(role); err != nil {
		return err
	}
	_, err = s.pg.Exec(ctx, `INSERT INTO profiles.tenant_roles (tenant_id, role) VALUES ($1::uuid,$2) ON CONFLICT (tenant_id, role) DO NOTHING`, tenant.ID, role)
	return err
}

func (s *Service) DeleteRole(ctx context.Context, tenantSlug, role string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return err
	}
	role = canonicalizeTenantRole(role)
	if err := validateTenantRole(role); err != nil {
		return err
	}
	if role == tenantOwnerRole {
		return ErrProtectedTenantRole
	}
	_, err = s.pg.Exec(ctx, `DELETE FROM profiles.tenant_roles WHERE tenant_id=$1::uuid AND role=$2`, tenant.ID, role)
	return err
}

func (s *Service) AssignRole(ctx context.Context, tenantSlug, userID, role string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return err
	}
	role = canonicalizeTenantRole(role)
	if err := validateTenantRole(role); err != nil {
		return err
	}
	// Lazily materialize an app DefaultRole template the first time it is
	// granted (default roles aren't seeded eagerly). This also creates the
	// tenant_roles row the assignment INSERT below requires.
	if err := s.materializeDefaultRole(ctx, tenant.ID, role); err != nil {
		return err
	}
	_, err = s.pg.Exec(ctx, `
		UPDATE profiles.tenant_memberships
		SET role=$3, updated_at=now()
		WHERE tenant_id=$1::uuid
		  AND user_id=$2::uuid
		  AND deleted_at IS NULL
		  AND EXISTS (SELECT 1 FROM profiles.tenant_roles WHERE tenant_id=$1::uuid AND role=$3)
	`, tenant.ID, userID, role)
	return err
}

func (s *Service) UnassignRole(ctx context.Context, tenantSlug, userID, role string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return err
	}
	role = canonicalizeTenantRole(role)
	if err := validateTenantRole(role); err != nil {
		return err
	}
	if role == tenantOwnerRole {
		var ownerCount int
		if err := s.pg.QueryRow(ctx, `
			SELECT COUNT(*)
			FROM profiles.tenant_memberships
			WHERE tenant_id=$1::uuid AND role=$2 AND deleted_at IS NULL
		`, tenant.ID, tenantOwnerRole).Scan(&ownerCount); err != nil {
			return err
		}
		if ownerCount <= 1 {
			return ErrLastTenantOwner
		}
	}
	_, err = s.pg.Exec(ctx, `
		UPDATE profiles.tenant_memberships
		SET role='member', updated_at=now()
		WHERE tenant_id=$1::uuid AND user_id=$2::uuid AND role=$3 AND deleted_at IS NULL
	`, tenant.ID, userID, role)
	return err
}

func (s *Service) ReadMemberRoles(ctx context.Context, tenantSlug, userID string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return nil, err
	}
	var role string
	err = s.pg.QueryRow(ctx, `
		SELECT role
		FROM profiles.tenant_memberships
		WHERE tenant_id=$1::uuid AND user_id=$2::uuid AND deleted_at IS NULL
	`, tenant.ID, userID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return []string{role}, nil
}

func (s *Service) IsTenantMember(ctx context.Context, tenantSlug, userID string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return false, err
	}
	var ok bool
	if err := s.pg.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM profiles.tenant_memberships WHERE tenant_id=$1::uuid AND user_id=$2::uuid AND deleted_at IS NULL)`, tenant.ID, userID).Scan(&ok); err != nil {
		return false, err
	}
	return ok, nil
}

func (s *Service) ListOrgMembers(ctx context.Context, tenantSlug string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return nil, err
	}
	rows, err := s.pg.Query(ctx, `
		SELECT user_id::text
		FROM profiles.tenant_memberships
		WHERE tenant_id=$1::uuid AND deleted_at IS NULL
		ORDER BY user_id::text ASC
	`, tenant.ID)
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

func (s *Service) ListOrgDefinedRoles(ctx context.Context, tenantSlug string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return nil, err
	}
	rows, err := s.pg.Query(ctx, `
		SELECT role
		FROM profiles.tenant_roles
		WHERE tenant_id=$1::uuid
		ORDER BY role ASC
	`, tenant.ID)
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
