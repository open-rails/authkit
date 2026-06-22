package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/open-rails/authkit/authbase"
	"github.com/open-rails/authkit/internal/db"
)

var (
	ErrOrgNotFound      = errors.New("org_not_found")
	ErrNotOrgMember     = errors.New("not_org_member")
	ErrInvalidOrgSlug   = errors.New("invalid_org_slug")
	ErrInvalidOrgRole   = errors.New("invalid_org_role")
	ErrInvalidOrgOwner  = errors.New("invalid_org_owner")
	ErrOrgLimitExceeded = errors.New("org_limit_exceeded")
	ErrProtectedOrgRole = errors.New("protected_org_role")
	ErrLastOrgOwner     = errors.New("cannot_remove_last_owner")
	ErrPersonalOrgOwner = errors.New("cannot_remove_personal_org_owner")
	// ErrRenameRateLimited is returned when a rename attempt happens
	// within renameCooldown of the previous rename for the same row.
	// Admin override paths (RenameOrgSlugForce / RenameUsernameForce)
	// bypass the check.
	ErrRenameRateLimited = errors.New("rename_rate_limited")
)

// Org is a minimal org record.
type Org struct {
	ID          string
	Slug        string
	IsPersonal  bool
	OwnerUserID string
}

// OrgMembership is defined in authbase (core-free) and re-exported here.
type OrgMembership = authbase.OrgMembership

// CreateOrgForUserRequest is the public org-registration contract. The
// org is owned by a real authenticated user; ownerless org creation is
// reserved for privileged bootstrap/admin APIs.
type CreateOrgForUserRequest struct {
	Slug        string
	OwnerUserID string
}

const (
	orgSlugMaxLen = 63
	orgRoleMaxLen = 64

	// These guardrails are hardcoded and intentionally not configurable.
	maxOrgsPerUser = 200

	// Reserved org role names. `owner` is the ONLY role authkit hardcodes — it is
	// the org's root authority (seeded at creation, undeletable). Every other
	// role, including any `admin` role, is defined by the platform/app, not here.
	orgOwnerRole  = "owner"
	orgMemberRole = "member"
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
	slug = strings.ToLower(strings.TrimSpace(slug))
	if err := validateOrgSlug(slug); err != nil {
		return nil, err
	}
	// Prefer current slug.
	row, err := s.q.OrgBySlug(ctx, slug)
	if err == nil {
		return &Org{ID: row.ID, Slug: row.Slug, IsPersonal: row.IsPersonal, OwnerUserID: row.OwnerUserID}, nil
	}
	// Fallback to renames table (issue #58). The org_renames row's
	// `org_id` always points at the live owner — every rename row of
	// the same org carries the same UUID — so any historical slug
	// resolves to the org currently holding it. Take the most recent
	// row to handle the rare case where two different orgs have used
	// this slug at different times (e.g. after hard-delete + reuse).
	ren, err := s.q.OrgBySlugViaRename(ctx, slug)
	if err != nil {
		return nil, ErrOrgNotFound
	}
	return &Org{ID: ren.ID, Slug: ren.Slug, IsPersonal: ren.IsPersonal, OwnerUserID: ren.OwnerUserID}, nil
}

// ResolveOrgByID resolves an active org by uuid string.
func (s *Service) ResolveOrgByID(ctx context.Context, id string) (*Org, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, ErrOrgNotFound
	}
	row, err := s.q.OrgSlugAndPersonalByID(ctx, id)
	if err != nil {
		return nil, ErrOrgNotFound
	}
	return &Org{ID: id, Slug: row.Slug, IsPersonal: row.IsPersonal}, nil
}

// CreateOrg creates an ownerless org for privileged bootstrap/admin
// callers. Public self-service org registration must use CreateOrgForUser
// so the org, owner membership, and owner role are created atomically.
func (s *Service) CreateOrg(ctx context.Context, slug string) (*Org, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	slug = strings.ToLower(strings.TrimSpace(slug))
	if err := validateOrgSlug(slug); err != nil {
		return nil, err
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	conflict, err := s.ownerSlugConflictExistsTx(ctx, tx, slug)
	if err != nil {
		return nil, err
	}
	if conflict {
		return nil, ErrOwnerSlugTaken
	}
	orgID, err := newUUIDV7String()
	if err != nil {
		return nil, err
	}
	qtx := s.qtx(tx)
	created, err := qtx.OrgInsert(ctx, db.OrgInsertParams{ID: orgID, Slug: slug})
	if err != nil {
		return nil, err
	}
	// Ensure the baseline owner/member roles always exist for every org.
	if err := qtx.OrgRolesSeedOwnerMember(ctx, db.OrgRolesSeedOwnerMemberParams{OrgID: created.ID, OwnerRole: orgOwnerRole, MemberRole: orgMemberRole}); err != nil {
		return nil, err
	}
	if err := s.seedOwnerGrants(ctx, qtx, created.ID); err != nil {
		return nil, err
	}
	if _, err := qtx.OwnerReservedNameDelete(ctx, slug); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &Org{ID: created.ID, Slug: created.Slug}, nil
}

// CreateOrgForUser transactionally creates a org and assigns the
// registering user as its sole initial owner. This is the core API behind
// public POST /orgs.
func (s *Service) CreateOrgForUser(ctx context.Context, req CreateOrgForUserRequest) (*Org, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	slug := strings.ToLower(strings.TrimSpace(req.Slug))
	if err := validateOrgSlug(slug); err != nil {
		return nil, err
	}
	ownerUserID := strings.TrimSpace(req.OwnerUserID)
	if ownerUserID == "" {
		return nil, ErrInvalidOrgOwner
	}
	if allowed, err := s.IsUserAllowed(ctx, ownerUserID); err != nil {
		if errors.Is(err, ErrUserNotFound) || errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidOrgOwner
		}
		return nil, err
	} else if !allowed {
		return nil, ErrInvalidOrgOwner
	}
	orgs, err := s.ListOrgMembershipsForUser(ctx, ownerUserID)
	if err != nil {
		return nil, err
	}
	if len(orgs) >= maxOrgsPerUser {
		return nil, ErrOrgLimitExceeded
	}
	if err := s.ensureOwnerSlugAvailable(ctx, slug, "", ""); err != nil {
		return nil, err
	}
	orgID, err := newUUIDV7String()
	if err != nil {
		return nil, err
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.qtx(tx)

	created, err := qtx.OrgInsert(ctx, db.OrgInsertParams{ID: orgID, Slug: slug})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrOwnerSlugTaken
		}
		return nil, err
	}
	if err := qtx.OrgRolesSeedOwnerMember(ctx, db.OrgRolesSeedOwnerMemberParams{OrgID: created.ID, OwnerRole: orgOwnerRole, MemberRole: orgMemberRole}); err != nil {
		return nil, err
	}
	if err := s.seedOwnerGrants(ctx, qtx, created.ID); err != nil {
		return nil, err
	}
	if err := qtx.OrgMembershipUpsertRole(ctx, db.OrgMembershipUpsertRoleParams{OrgID: created.ID, UserID: ownerUserID, Role: orgOwnerRole}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &Org{ID: created.ID, Slug: created.Slug, OwnerUserID: ownerUserID}, nil
}

// RenameOrgSlug renames a non-personal org. Subject to the 72h
// `renameCooldown`. Personal orgs are renamed implicitly by the user-
// rename flow (see service.go) and reject this entrypoint with
// `ErrPersonalOrgLocked`.
//
// `actorUserID` is recorded on the rename audit row. Pass empty string
// when the caller doesn't have an authenticated user (e.g. internal
// admin tooling without an actor); the column is nullable.
func (s *Service) RenameOrgSlug(ctx context.Context, orgID, newSlug, actorUserID string) error {
	return s.renameOrgSlugImpl(ctx, orgID, newSlug, actorUserID, false)
}

// RenameOrgSlugForce is the admin-override variant that skips the 72h
// cooldown check. Otherwise identical to RenameOrgSlug. Caller is
// responsible for gating this behind admin scope upstream.
func (s *Service) RenameOrgSlugForce(ctx context.Context, orgID, newSlug, actorUserID string) error {
	return s.renameOrgSlugImpl(ctx, orgID, newSlug, actorUserID, true)
}

func (s *Service) renameOrgSlugImpl(ctx context.Context, orgID, newSlug, actorUserID string, bypassCooldown bool) error {
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
	qtx := s.qtx(tx)

	cur, err := qtx.OrgSlugAndPersonalByID(ctx, orgID)
	if err != nil {
		return ErrOrgNotFound
	}
	oldSlug := cur.Slug
	if cur.IsPersonal {
		return ErrPersonalOrgLocked
	}
	if strings.EqualFold(oldSlug, newSlug) {
		return nil
	}

	// Cooldown check (issue #58). Walks the (org_id, renamed_at DESC)
	// index to grab the most recent rename for this org and rejects if
	// it's within the renameCooldown window.
	if !bypassCooldown {
		lastRenamedAt, err := qtx.OrgLastRenamedAt(ctx, orgID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil && time.Since(lastRenamedAt) < renameCooldown {
			return ErrRenameRateLimited
		}
	}

	if err := s.ensureOwnerSlugAvailable(ctx, newSlug, "", orgID); err != nil {
		return err
	}

	// Audit row in org_renames. Source of truth for both forwarding
	// (from_slug → current owner) and reverse history (org_id → all
	// historical slugs in order).
	if err := qtx.OrgRenameInsert(ctx, db.OrgRenameInsertParams{OrgID: orgID, FromSlug: strings.ToLower(strings.TrimSpace(oldSlug))}); err != nil {
		return err
	}

	if err := qtx.OrgUpdateSlug(ctx, db.OrgUpdateSlugParams{Slug: newSlug, ID: orgID}); err != nil {
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
	slugs, err := s.q.OrgSlugsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(slugs) > maxOrgsPerUser {
		return nil, fmt.Errorf("org_membership_limit_exceeded")
	}
	return slugs, nil
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
	return s.q.OrgMemberAdd(ctx, db.OrgMemberAddParams{OrgID: org.ID, UserID: userID})
}

func (s *Service) RemoveMember(ctx context.Context, orgSlug, userID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return err
	}
	if org.IsPersonal && strings.EqualFold(strings.TrimSpace(org.OwnerUserID), strings.TrimSpace(userID)) {
		return ErrPersonalOrgOwner
	}
	// Prevent removing the last owner from the org.
	isOwner, err := s.q.OrgMemberHasRole(ctx, db.OrgMemberHasRoleParams{OrgID: org.ID, UserID: userID, Role: orgOwnerRole})
	if err != nil {
		return err
	}
	if isOwner {
		ownerCount, err := s.q.OrgRoleMemberCount(ctx, db.OrgRoleMemberCountParams{OrgID: org.ID, Role: orgOwnerRole})
		if err != nil {
			return err
		}
		if ownerCount <= 1 {
			return ErrLastOrgOwner
		}
	}
	return s.q.OrgMemberSoftDelete(ctx, db.OrgMemberSoftDeleteParams{OrgID: org.ID, UserID: userID})
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
	return s.q.OrgRoleDefine(ctx, db.OrgRoleDefineParams{OrgID: org.ID, Role: role})
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
	return s.q.OrgRoleDelete(ctx, db.OrgRoleDeleteParams{OrgID: org.ID, Role: role})
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
	// Lazily materialize an app DefaultRole template the first time it is
	// granted (default roles aren't seeded eagerly). This also creates the
	// org_roles row the assignment INSERT below requires.
	if err := s.materializeDefaultRole(ctx, org.ID, role); err != nil {
		return err
	}
	return s.q.OrgMembershipSetRole(ctx, db.OrgMembershipSetRoleParams{OrgID: org.ID, UserID: userID, Role: role})
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
		ownerCount, err := s.q.OrgRoleMemberCount(ctx, db.OrgRoleMemberCountParams{OrgID: org.ID, Role: orgOwnerRole})
		if err != nil {
			return err
		}
		if ownerCount <= 1 {
			return ErrLastOrgOwner
		}
	}
	return s.q.OrgMembershipResetRole(ctx, db.OrgMembershipResetRoleParams{OrgID: org.ID, UserID: userID, Role: role})
}

func (s *Service) ReadMemberRoles(ctx context.Context, orgSlug, userID string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return nil, err
	}
	role, err := s.q.OrgMemberRole(ctx, db.OrgMemberRoleParams{OrgID: org.ID, UserID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return []string{role}, nil
}

func (s *Service) IsOrgMember(ctx context.Context, orgSlug, userID string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return false, err
	}
	return s.q.OrgMembershipExists(ctx, db.OrgMembershipExistsParams{OrgID: org.ID, UserID: userID})
}

func (s *Service) ListOrgMembers(ctx context.Context, orgSlug string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return nil, err
	}
	return s.q.OrgMemberIDs(ctx, org.ID)
}

func (s *Service) ListOrgDefinedRoles(ctx context.Context, orgSlug string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return nil, err
	}
	return s.q.OrgDefinedRoles(ctx, org.ID)
}
