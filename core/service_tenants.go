package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/open-rails/authkit/internal/db"
)

var (
	ErrTenantNotFound      = errors.New("tenant_not_found")
	ErrNotTenantMember     = errors.New("not_tenant_member")
	ErrInvalidTenantSlug   = errors.New("invalid_tenant_slug")
	ErrInvalidTenantRole   = errors.New("invalid_tenant_role")
	ErrInvalidTenantOwner  = errors.New("invalid_tenant_owner")
	ErrTenantLimitExceeded = errors.New("tenant_limit_exceeded")
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

// CreateTenantForUserRequest is the public tenant-registration contract. The
// tenant is owned by a real authenticated user; ownerless tenant creation is
// reserved for privileged bootstrap/admin APIs.
type CreateTenantForUserRequest struct {
	Slug        string
	OwnerUserID string
}

const (
	tenantSlugMaxLen = 63
	tenantRoleMaxLen = 64

	// These guardrails are hardcoded and intentionally not configurable.
	maxTenantsPerUser = 200

	// Reserved tenant role names. `owner` is the ONLY role authkit hardcodes — it is
	// the tenant's root authority (seeded at creation, undeletable). Every other
	// role, including any `admin` role, is defined by the platform/app, not here.
	tenantOwnerRole  = "owner"
	tenantMemberRole = "member"
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
	// Prefer current slug.
	row, err := s.q.TenantBySlug(ctx, slug)
	if err == nil {
		return &Tenant{ID: row.ID, Slug: row.Slug, IsPersonal: row.IsPersonal, OwnerUserID: row.OwnerUserID}, nil
	}
	// Fallback to renames table (issue #58). The tenant_renames row's
	// `tenant_id` always points at the live owner — every rename row of
	// the same tenant carries the same UUID — so any historical slug
	// resolves to the tenant currently holding it. Take the most recent
	// row to handle the rare case where two different tenants have used
	// this slug at different times (e.g. after hard-delete + reuse).
	ren, err := s.q.TenantBySlugViaRename(ctx, slug)
	if err != nil {
		return nil, ErrTenantNotFound
	}
	return &Tenant{ID: ren.ID, Slug: ren.Slug, IsPersonal: ren.IsPersonal, OwnerUserID: ren.OwnerUserID}, nil
}

// CreateTenant creates an ownerless tenant for privileged bootstrap/admin
// callers. Public self-service tenant registration must use CreateTenantForUser
// so the tenant, owner membership, and owner role are created atomically.
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
	created, err := s.q.TenantInsert(ctx, db.TenantInsertParams{ID: tenantID, Slug: slug})
	if err != nil {
		return nil, err
	}
	// Ensure the baseline owner/member roles always exist for every tenant.
	if err := s.q.TenantRolesSeedOwnerMember(ctx, db.TenantRolesSeedOwnerMemberParams{TenantID: created.ID, OwnerRole: tenantOwnerRole, MemberRole: tenantMemberRole}); err != nil {
		return nil, err
	}
	// Seed owner=`*` + any app-declared default roles (e.g. admin).
	if err := s.seedRolePermissionDefaults(ctx, created.ID); err != nil {
		return nil, err
	}
	return &Tenant{ID: created.ID, Slug: created.Slug}, nil
}

// CreateTenantForUser transactionally creates a tenant and assigns the
// registering user as its sole initial owner. This is the core API behind
// public POST /tenants.
func (s *Service) CreateTenantForUser(ctx context.Context, req CreateTenantForUserRequest) (*Tenant, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	slug := strings.ToLower(strings.TrimSpace(req.Slug))
	if err := validateTenantSlug(slug); err != nil {
		return nil, err
	}
	ownerUserID := strings.TrimSpace(req.OwnerUserID)
	if ownerUserID == "" {
		return nil, ErrInvalidTenantOwner
	}
	if allowed, err := s.IsUserAllowed(ctx, ownerUserID); err != nil {
		if errors.Is(err, ErrUserNotFound) || errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidTenantOwner
		}
		return nil, err
	} else if !allowed {
		return nil, ErrInvalidTenantOwner
	}
	tenants, err := s.ListTenantMembershipsForUser(ctx, ownerUserID)
	if err != nil {
		return nil, err
	}
	if len(tenants) >= maxTenantsPerUser {
		return nil, ErrTenantLimitExceeded
	}
	if err := s.ensureOwnerSlugAvailable(ctx, slug, "", ""); err != nil {
		return nil, err
	}
	tenantID, err := newUUIDV7String()
	if err != nil {
		return nil, err
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.q.WithTx(tx)

	created, err := qtx.TenantInsert(ctx, db.TenantInsertParams{ID: tenantID, Slug: slug})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrOwnerSlugTaken
		}
		return nil, err
	}
	if err := qtx.TenantRolesSeedOwnerMember(ctx, db.TenantRolesSeedOwnerMemberParams{TenantID: created.ID, OwnerRole: tenantOwnerRole, MemberRole: tenantMemberRole}); err != nil {
		return nil, err
	}
	if err := qtx.TenantRolePermissionInsert(ctx, db.TenantRolePermissionInsertParams{TenantID: created.ID, Role: tenantOwnerRole, Permission: PermWildcard}); err != nil {
		return nil, err
	}
	if err := qtx.TenantMembershipUpsertRole(ctx, db.TenantMembershipUpsertRoleParams{TenantID: created.ID, UserID: ownerUserID, Role: tenantOwnerRole}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &Tenant{ID: created.ID, Slug: created.Slug, OwnerUserID: ownerUserID}, nil
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
	qtx := s.q.WithTx(tx)

	cur, err := qtx.TenantSlugAndPersonalByID(ctx, tenantID)
	if err != nil {
		return ErrTenantNotFound
	}
	oldSlug := cur.Slug
	if cur.IsPersonal {
		return ErrPersonalTenantLocked
	}
	if strings.EqualFold(oldSlug, newSlug) {
		return nil
	}

	// Cooldown check (issue #58). Walks the (tenant_id, renamed_at DESC)
	// index to grab the most recent rename for this tenant and rejects if
	// it's within the renameCooldown window.
	if !bypassCooldown {
		lastRenamedAt, err := qtx.TenantLastRenamedAt(ctx, tenantID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil && time.Since(lastRenamedAt) < renameCooldown {
			return ErrRenameRateLimited
		}
	}

	if err := s.ensureOwnerSlugAvailable(ctx, newSlug, "", tenantID); err != nil {
		return err
	}

	// Audit row in tenant_renames. Source of truth for both forwarding
	// (from_slug → current owner) and reverse history (tenant_id → all
	// historical slugs in order).
	if err := qtx.TenantRenameInsert(ctx, db.TenantRenameInsertParams{TenantID: tenantID, FromSlug: strings.ToLower(strings.TrimSpace(oldSlug))}); err != nil {
		return err
	}

	if err := qtx.TenantUpdateSlug(ctx, db.TenantUpdateSlugParams{Slug: newSlug, ID: tenantID}); err != nil {
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
	slugs, err := s.q.TenantSlugsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(slugs) > maxTenantsPerUser {
		return nil, fmt.Errorf("tenant_membership_limit_exceeded")
	}
	return slugs, nil
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
	if tenants, e := s.ListTenantMembershipsForUser(ctx, userID); e == nil && len(tenants) >= maxTenantsPerUser {
		return fmt.Errorf("tenant_membership_limit_exceeded")
	}
	return s.q.TenantMemberAdd(ctx, db.TenantMemberAddParams{TenantID: tenant.ID, UserID: userID})
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
	isOwner, err := s.q.TenantMemberHasRole(ctx, db.TenantMemberHasRoleParams{TenantID: tenant.ID, UserID: userID, Role: tenantOwnerRole})
	if err != nil {
		return err
	}
	if isOwner {
		ownerCount, err := s.q.TenantRoleMemberCount(ctx, db.TenantRoleMemberCountParams{TenantID: tenant.ID, Role: tenantOwnerRole})
		if err != nil {
			return err
		}
		if ownerCount <= 1 {
			return ErrLastTenantOwner
		}
	}
	return s.q.TenantMemberSoftDelete(ctx, db.TenantMemberSoftDeleteParams{TenantID: tenant.ID, UserID: userID})
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
	return s.q.TenantRoleDefine(ctx, db.TenantRoleDefineParams{TenantID: tenant.ID, Role: role})
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
	return s.q.TenantRoleDelete(ctx, db.TenantRoleDeleteParams{TenantID: tenant.ID, Role: role})
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
	return s.q.TenantMembershipSetRole(ctx, db.TenantMembershipSetRoleParams{TenantID: tenant.ID, UserID: userID, Role: role})
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
		ownerCount, err := s.q.TenantRoleMemberCount(ctx, db.TenantRoleMemberCountParams{TenantID: tenant.ID, Role: tenantOwnerRole})
		if err != nil {
			return err
		}
		if ownerCount <= 1 {
			return ErrLastTenantOwner
		}
	}
	return s.q.TenantMembershipResetRole(ctx, db.TenantMembershipResetRoleParams{TenantID: tenant.ID, UserID: userID, Role: role})
}

func (s *Service) ReadMemberRoles(ctx context.Context, tenantSlug, userID string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return nil, err
	}
	role, err := s.q.TenantMemberRole(ctx, db.TenantMemberRoleParams{TenantID: tenant.ID, UserID: userID})
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
	return s.q.TenantMembershipExists(ctx, db.TenantMembershipExistsParams{TenantID: tenant.ID, UserID: userID})
}

func (s *Service) ListTenantMembers(ctx context.Context, tenantSlug string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return nil, err
	}
	return s.q.TenantMemberIDs(ctx, tenant.ID)
}

func (s *Service) ListTenantDefinedRoles(ctx context.Context, tenantSlug string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return nil, err
	}
	return s.q.TenantDefinedRoles(ctx, tenant.ID)
}
