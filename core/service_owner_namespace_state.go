package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/db"
)

type OwnerNamespaceState string

const (
	OwnerNamespaceStateRestrictedName OwnerNamespaceState = "restricted_name"
	OwnerNamespaceStateParkedTenant   OwnerNamespaceState = "parked_tenant"
	OwnerNamespaceStateRegistered     OwnerNamespaceState = "registered_tenant"
)

var (
	ErrOwnerNamespaceNotFound          = errors.New("owner_namespace_not_found")
	ErrInvalidOwnerNamespaceState      = errors.New("invalid_owner_namespace_state")
	ErrInvalidOwnerNamespaceTransition = errors.New("invalid_owner_namespace_transition")
	ErrOwnerMembershipRequired         = errors.New("owner_membership_required")
	ErrOwnerNamespaceAlreadyClaimed    = errors.New("owner_namespace_already_claimed")
	ErrOwnerNamespaceBatchEmpty        = errors.New("owner_namespace_batch_empty")
)

func normalizeOwnerNamespaceState(state OwnerNamespaceState) OwnerNamespaceState {
	s := strings.ToLower(strings.TrimSpace(string(state)))
	switch OwnerNamespaceState(s) {
	case OwnerNamespaceStateRestrictedName:
		return OwnerNamespaceStateRestrictedName
	case OwnerNamespaceStateParkedTenant:
		return OwnerNamespaceStateParkedTenant
	case OwnerNamespaceStateRegistered:
		return OwnerNamespaceStateRegistered
	default:
		return ""
	}
}

func validateOwnerNamespaceState(state OwnerNamespaceState) error {
	s := normalizeOwnerNamespaceState(state)
	if s == "" {
		return ErrInvalidOwnerNamespaceState
	}
	if s == OwnerNamespaceStateRestrictedName {
		return ErrInvalidOwnerNamespaceState
	}
	return nil
}

func (s *Service) ownerReservedNameExistsTx(ctx context.Context, tx pgx.Tx, slug string) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("tx required")
	}
	slug = normalizeReservedSlug(slug)
	return s.qtx(tx).OwnerReservedNameExists(ctx, slug)
}

func (s *Service) upsertOwnerReservedNameTx(ctx context.Context, tx pgx.Tx, slug string) error {
	if tx == nil {
		return fmt.Errorf("tx required")
	}
	slug = normalizeReservedSlug(slug)
	return s.qtx(tx).OwnerReservedNameUpsert(ctx, slug)
}

func (s *Service) deleteOwnerReservedNameTx(ctx context.Context, tx pgx.Tx, slug string) error {
	if tx == nil {
		return fmt.Errorf("tx required")
	}
	slug = normalizeReservedSlug(slug)
	_, err := s.qtx(tx).OwnerReservedNameDelete(ctx, slug)
	return err
}

func (s *Service) ownerSlugConflictExistsTx(ctx context.Context, tx pgx.Tx, slug string) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("tx required")
	}
	slug = strings.ToLower(strings.TrimSpace(slug))
	reuseCutoff := time.Now().UTC().Add(-renameReuseHold)
	return s.qtx(tx).OwnerSlugConflictExists(ctx, db.OwnerSlugConflictExistsParams{Slug: slug, ReuseCutoff: reuseCutoff})
}

func (s *Service) IsUserReserved(ctx context.Context, userID string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	if strings.TrimSpace(userID) == "" {
		return false, fmt.Errorf("invalid_user")
	}
	reserved, err := s.q.UserIsReserved(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrUserNotFound
		}
		return false, err
	}
	return reserved, nil
}

func (s *Service) GetTenantNamespaceState(ctx context.Context, tenantID string) (OwnerNamespaceState, error) {
	if err := s.requirePG(); err != nil {
		return "", err
	}
	if strings.TrimSpace(tenantID) == "" {
		return "", fmt.Errorf("invalid_tenant")
	}
	row, err := s.q.TenantNamespaceStateByID(ctx, tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrTenantNotFound
		}
		return "", err
	}
	state := normalizeOwnerNamespaceState(OwnerNamespaceState(row.StateRaw))
	if state != "" {
		return state, nil
	}
	if row.Reserved {
		return OwnerNamespaceStateParkedTenant, nil
	}
	return OwnerNamespaceStateRegistered, nil
}

func (s *Service) setTenantNamespaceStateTx(ctx context.Context, tx pgx.Tx, tenantID string, state OwnerNamespaceState) error {
	if tx == nil {
		return fmt.Errorf("tx required")
	}
	state = normalizeOwnerNamespaceState(state)
	if err := validateOwnerNamespaceState(state); err != nil {
		return err
	}
	reserved := state == OwnerNamespaceStateParkedTenant
	n, err := s.qtx(tx).TenantSetNamespaceState(ctx, db.TenantSetNamespaceStateParams{ID: tenantID, State: string(state), Reserved: reserved})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrTenantNotFound
	}
	return nil
}

func (s *Service) SetTenantNamespaceState(ctx context.Context, tenantID string, state OwnerNamespaceState) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	if strings.TrimSpace(tenantID) == "" {
		return fmt.Errorf("invalid_tenant")
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.setTenantNamespaceStateTx(ctx, tx, tenantID, state); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) GetOwnerNamespaceStateBySlug(ctx context.Context, slug string) (OwnerNamespaceState, error) {
	if err := s.requirePG(); err != nil {
		return "", err
	}
	slug = normalizeReservedSlug(slug)
	if err := validateTenantSlug(slug); err != nil {
		return "", err
	}
	exists, err := s.q.OwnerReservedNameExists(ctx, slug)
	if err != nil {
		return "", err
	}
	if exists {
		return OwnerNamespaceStateRestrictedName, nil
	}
	tenant, err := s.ResolveTenantBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			return "", ErrOwnerNamespaceNotFound
		}
		return "", err
	}
	state, err := s.GetTenantNamespaceState(ctx, tenant.ID)
	if err != nil {
		return "", err
	}
	return state, nil
}

// ParkTenantNamespace parks `slug` as a parked_tenant. Works whether or not the slug
// is currently in owner_reserved_names — any caller-supplied slug is parkable,
// even bootstrap-reserved names like 'root' or 'admin'. If a reserved-name row
// exists it's deleted as part of the transaction. Internal-library API only —
// not exposed publicly.
func (s *Service) ParkTenantNamespace(ctx context.Context, slug string) (tenantID string, created bool, err error) {
	if err := s.requirePG(); err != nil {
		return "", false, err
	}
	slug = normalizeReservedSlug(slug)
	if err := validateTenantSlug(slug); err != nil {
		return "", false, err
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	existing, err := s.qtx(tx).TenantIDPersonalBySlug(ctx, slug)
	existingID := existing.ID
	switch {
	case err == nil:
		if existing.IsPersonal {
			return "", false, ErrInvalidOwnerNamespaceTransition
		}
		if err := s.setTenantNamespaceStateTx(ctx, tx, existingID, OwnerNamespaceStateParkedTenant); err != nil {
			return "", false, err
		}
		if err := s.deleteOwnerReservedNameTx(ctx, tx, slug); err != nil {
			return "", false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return "", false, err
		}
		return strings.TrimSpace(existingID), false, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return "", false, err
	}

	conflict, err := s.ownerSlugConflictExistsTx(ctx, tx, slug)
	if err != nil {
		return "", false, err
	}
	if conflict {
		return "", false, ErrOwnerSlugTaken
	}
	tenantIDToInsert, err := newUUIDV7String()
	if err != nil {
		return "", false, err
	}
	tenantID, err = s.qtx(tx).TenantInsertWithState(ctx, db.TenantInsertWithStateParams{ID: tenantIDToInsert, Slug: slug, State: string(OwnerNamespaceStateParkedTenant)})
	if err != nil {
		return "", false, err
	}
	if err := s.qtx(tx).TenantRolesSeedOwnerMember(ctx, db.TenantRolesSeedOwnerMemberParams{TenantID: tenantID, OwnerRole: tenantOwnerRole, MemberRole: tenantMemberRole}); err != nil {
		return "", false, err
	}
	if err := s.deleteOwnerReservedNameTx(ctx, tx, slug); err != nil {
		return "", false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", false, err
	}
	return strings.TrimSpace(tenantID), true, nil
}

func (s *Service) PromoteParkedTenantToRegistered(ctx context.Context, slug, ownerUserID string) (tenantID string, err error) {
	if err := s.requirePG(); err != nil {
		return "", err
	}
	slug = normalizeReservedSlug(slug)
	if err := validateTenantSlug(slug); err != nil {
		return "", err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, slug)
	if err != nil {
		return "", err
	}
	state, err := s.GetTenantNamespaceState(ctx, tenant.ID)
	if err != nil {
		return "", err
	}
	if state != OwnerNamespaceStateParkedTenant {
		return "", ErrInvalidOwnerNamespaceTransition
	}
	return s.claimParkedTenantToRegistered(ctx, tenant, ownerUserID)
}

// PromoteReservedNameToRegistered supports direct handoff in one operation:
//
//	restricted_name -> parked_tenant -> registered_tenant
//
// It is idempotent for already-registered tenants and optionally ensures owner membership.
func (s *Service) PromoteReservedNameToRegistered(ctx context.Context, slug, ownerUserID string) (tenantID string, created bool, err error) {
	if err := s.requirePG(); err != nil {
		return "", false, err
	}
	slug = normalizeReservedSlug(slug)
	if err := validateTenantSlug(slug); err != nil {
		return "", false, err
	}
	state, err := s.GetOwnerNamespaceStateBySlug(ctx, slug)
	if err != nil {
		return "", false, err
	}
	switch state {
	case OwnerNamespaceStateRestrictedName:
		_, created, err = s.ParkTenantNamespace(ctx, slug)
		if err != nil {
			return "", false, err
		}
		registeredID, err := s.PromoteParkedTenantToRegistered(ctx, slug, ownerUserID)
		if err != nil {
			return "", false, err
		}
		return strings.TrimSpace(registeredID), created, nil
	case OwnerNamespaceStateParkedTenant:
		registeredID, err := s.PromoteParkedTenantToRegistered(ctx, slug, ownerUserID)
		if err != nil {
			return "", false, err
		}
		return strings.TrimSpace(registeredID), false, nil
	case OwnerNamespaceStateRegistered:
		tenant, err := s.ResolveTenantBySlug(ctx, slug)
		if err != nil {
			return "", false, err
		}
		ownerUserID = strings.TrimSpace(ownerUserID)
		if ownerUserID == "" {
			ownerCount, err := s.countActiveTenantOwners(ctx, strings.TrimSpace(tenant.ID))
			if err != nil {
				return "", false, err
			}
			if ownerCount < 1 {
				return "", false, ErrOwnerMembershipRequired
			}
			return strings.TrimSpace(tenant.ID), false, nil
		}
		if err := s.AddMember(ctx, tenant.Slug, ownerUserID); err != nil {
			return "", false, err
		}
		if err := s.AssignRole(ctx, tenant.Slug, ownerUserID, tenantOwnerRole); err != nil {
			return "", false, err
		}
		ownerCount, err := s.countActiveTenantOwners(ctx, strings.TrimSpace(tenant.ID))
		if err != nil {
			return "", false, err
		}
		if ownerCount < 1 {
			return "", false, ErrOwnerMembershipRequired
		}
		return strings.TrimSpace(tenant.ID), false, nil
	default:
		return "", false, ErrInvalidOwnerNamespaceTransition
	}
}

func (s *Service) claimParkedTenantToRegistered(ctx context.Context, tenant *Tenant, ownerUserID string) (tenantID string, err error) {
	if tenant == nil || strings.TrimSpace(tenant.ID) == "" {
		return "", ErrTenantNotFound
	}
	ownerUserID = strings.TrimSpace(ownerUserID)
	if ownerUserID == "" {
		return "", ErrOwnerMembershipRequired
	}
	ownerUser, err := s.getUserByID(ctx, ownerUserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrUserNotFound
		}
		return "", err
	}
	if ownerUser == nil || ownerUser.DeletedAt != nil {
		return "", ErrUserNotFound
	}
	ownerCount, err := s.countActiveTenantOwners(ctx, strings.TrimSpace(tenant.ID))
	if err != nil {
		return "", err
	}
	if ownerCount > 0 {
		return "", ErrOwnerNamespaceAlreadyClaimed
	}
	// The park/claim path doesn't go through CreateTenant, so seed the owner role
	// + its `*` permission here (idempotent). Without this a claimed tenant (e.g. a
	// reserved namespace like tensorhub's `root`) has NO role-permissions — not
	// even owner=* — so its owner holds nothing and only a global-admin bypass
	// works. App DefaultRoles stay lazy (materialized on first grant).
	if err := s.q.TenantRoleDefine(ctx, db.TenantRoleDefineParams{TenantID: tenant.ID, Role: tenantOwnerRole}); err != nil {
		return "", err
	}
	if err := s.seedRolePermissionDefaults(ctx, tenant.ID); err != nil {
		return "", err
	}
	if err := s.AddMember(ctx, tenant.Slug, ownerUserID); err != nil {
		return "", err
	}
	if err := s.AssignRole(ctx, tenant.Slug, ownerUserID, tenantOwnerRole); err != nil {
		return "", err
	}
	ownerCount, err = s.countActiveTenantOwners(ctx, strings.TrimSpace(tenant.ID))
	if err != nil {
		return "", err
	}
	if ownerCount < 1 {
		return "", ErrOwnerMembershipRequired
	}
	if err := s.SetTenantNamespaceState(ctx, tenant.ID, OwnerNamespaceStateRegistered); err != nil {
		return "", err
	}
	_, _ = s.q.OwnerReservedNameDelete(ctx, normalizeReservedSlug(tenant.Slug))
	return strings.TrimSpace(tenant.ID), nil
}

func normalizeOwnerNamespaceSlugs(raw []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		slug := normalizeReservedSlug(item)
		if slug == "" {
			continue
		}
		if err := validateTenantSlug(slug); err != nil {
			return nil, err
		}
		if _, exists := seen[slug]; exists {
			continue
		}
		seen[slug] = struct{}{}
		out = append(out, slug)
	}
	if len(out) == 0 {
		return nil, ErrOwnerNamespaceBatchEmpty
	}
	return out, nil
}

// RestrictOwnerNamespaceSlugs adds slugs to the restricted-name blocklist.
// It is an admin operation separate from park/claim tenant lifecycle transitions.
func (s *Service) RestrictOwnerNamespaceSlugs(ctx context.Context, slugs []string) (restricted []string, alreadyRestricted []string, err error) {
	if err := s.requirePG(); err != nil {
		return nil, nil, err
	}
	slugs, err = normalizeOwnerNamespaceSlugs(slugs)
	if err != nil {
		return nil, nil, err
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	restricted = make([]string, 0, len(slugs))
	alreadyRestricted = make([]string, 0)
	for _, slug := range slugs {
		exists, err := s.ownerReservedNameExistsTx(ctx, tx, slug)
		if err != nil {
			return nil, nil, err
		}
		if exists {
			alreadyRestricted = append(alreadyRestricted, slug)
			continue
		}
		conflict, err := s.ownerSlugConflictExistsTx(ctx, tx, slug)
		if err != nil {
			return nil, nil, err
		}
		if conflict {
			return nil, nil, ErrOwnerSlugTaken
		}
		if err := s.upsertOwnerReservedNameTx(ctx, tx, slug); err != nil {
			return nil, nil, err
		}
		restricted = append(restricted, slug)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	return restricted, alreadyRestricted, nil
}

// UnrestrictOwnerNamespaceSlugs removes slugs from the restricted-name blocklist.
func (s *Service) UnrestrictOwnerNamespaceSlugs(ctx context.Context, slugs []string) (unrestricted []string, notRestricted []string, err error) {
	if err := s.requirePG(); err != nil {
		return nil, nil, err
	}
	slugs, err = normalizeOwnerNamespaceSlugs(slugs)
	if err != nil {
		return nil, nil, err
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	unrestricted = make([]string, 0, len(slugs))
	notRestricted = make([]string, 0)
	for _, slug := range slugs {
		n, err := s.qtx(tx).OwnerReservedNameDelete(ctx, slug)
		if err != nil {
			return nil, nil, err
		}
		if n == 0 {
			notRestricted = append(notRestricted, slug)
			continue
		}
		unrestricted = append(unrestricted, slug)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	return unrestricted, notRestricted, nil
}

// ClaimTenantNamespace claims tenant ownership for a specific existing user.
//
// Rules:
//   - parked_tenant -> registered_tenant + owner membership assignment
//   - already-registered tenants return ErrOwnerNamespaceAlreadyClaimed
//   - restricted_name (or missing namespace) creates the tenant if needed, then claims it
//   - owner user must exist and not be soft-deleted
func (s *Service) ClaimTenantNamespace(ctx context.Context, slug, ownerUserID string) (tenantID string, created bool, err error) {
	if err := s.requirePG(); err != nil {
		return "", false, err
	}
	slug = normalizeReservedSlug(slug)
	if err := validateTenantSlug(slug); err != nil {
		return "", false, err
	}
	ownerUserID = strings.TrimSpace(ownerUserID)
	if ownerUserID == "" {
		return "", false, ErrOwnerMembershipRequired
	}
	ownerUser, err := s.getUserByID(ctx, ownerUserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, ErrUserNotFound
		}
		return "", false, err
	}
	if ownerUser == nil || ownerUser.DeletedAt != nil {
		return "", false, ErrUserNotFound
	}

	state, err := s.GetOwnerNamespaceStateBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, ErrOwnerNamespaceNotFound) {
			tenant, createErr := s.CreateTenant(ctx, slug)
			if createErr != nil {
				return "", false, createErr
			}
			claimedID, claimErr := s.claimParkedTenantToRegistered(ctx, tenant, ownerUserID)
			if claimErr != nil {
				return "", false, claimErr
			}
			return claimedID, true, nil
		}
		return "", false, err
	}

	switch state {
	case OwnerNamespaceStateParkedTenant:
		tenant, resolveErr := s.ResolveTenantBySlug(ctx, slug)
		if resolveErr != nil {
			return "", false, resolveErr
		}
		claimedID, claimErr := s.claimParkedTenantToRegistered(ctx, tenant, ownerUserID)
		if claimErr != nil {
			return "", false, claimErr
		}
		return claimedID, false, nil
	case OwnerNamespaceStateRestrictedName:
		tenant, resolveErr := s.ResolveTenantBySlug(ctx, slug)
		switch {
		case resolveErr == nil:
			ownerCount, countErr := s.countActiveTenantOwners(ctx, strings.TrimSpace(tenant.ID))
			if countErr != nil {
				return "", false, countErr
			}
			if ownerCount > 0 {
				return "", false, ErrOwnerNamespaceAlreadyClaimed
			}
		case errors.Is(resolveErr, ErrTenantNotFound):
		default:
			return "", false, resolveErr
		}

		parkedID, parkedCreated, parkErr := s.ParkTenantNamespace(ctx, slug)
		if parkErr != nil {
			return "", false, parkErr
		}
		parkedTenant, resolveErr := s.ResolveTenantBySlug(ctx, slug)
		if resolveErr != nil {
			return "", false, resolveErr
		}
		claimedID, claimErr := s.claimParkedTenantToRegistered(ctx, parkedTenant, ownerUserID)
		if claimErr != nil {
			return "", false, claimErr
		}
		if strings.TrimSpace(parkedID) != "" && strings.TrimSpace(parkedID) != strings.TrimSpace(claimedID) {
			return "", false, ErrInvalidOwnerNamespaceTransition
		}
		return claimedID, parkedCreated, nil
	case OwnerNamespaceStateRegistered:
		return "", false, ErrOwnerNamespaceAlreadyClaimed
	default:
		return "", false, ErrInvalidOwnerNamespaceTransition
	}
}

// ParkUserNamespace ensures a slug is represented as a parked user namespace.
//
// Behavior:
//   - If no same-slug user exists, creates a placeholder user (and personal tenant), then parks it.
//   - If a same-slug non-personal tenant exists, returns ErrInvalidOwnerNamespaceTransition.
//   - Requires the slug to be valid and available for user ownership semantics.
func (s *Service) ParkUserNamespace(ctx context.Context, slug string) (userID, tenantID string, created bool, err error) {
	if err := s.requirePG(); err != nil {
		return "", "", false, err
	}
	slug = normalizeReservedSlug(slug)
	if err := validateTenantSlug(slug); err != nil {
		return "", "", false, err
	}

	if tenant, err := s.ResolveTenantBySlug(ctx, slug); err == nil && tenant != nil {
		if !tenant.IsPersonal {
			return "", "", false, ErrInvalidOwnerNamespaceTransition
		}
	} else if err != nil && !errors.Is(err, ErrTenantNotFound) {
		return "", "", false, err
	}

	switch id, _, err := s.ResolveUserBySlug(ctx, slug); {
	case err == nil:
		userID = strings.TrimSpace(id)
	case errors.Is(err, ErrUserNotFound):
		state, stateErr := s.GetOwnerNamespaceStateBySlug(ctx, slug)
		if stateErr == nil && state == OwnerNamespaceStateRestrictedName {
			if _, _, unrestrictErr := s.UnrestrictOwnerNamespaceSlugs(ctx, []string{slug}); unrestrictErr != nil {
				return "", "", false, unrestrictErr
			}
		} else if stateErr != nil && !errors.Is(stateErr, ErrOwnerNamespaceNotFound) {
			return "", "", false, stateErr
		}

		u, createErr := s.CreateUser(ctx, "", slug)
		if createErr != nil {
			return "", "", false, createErr
		}
		if u == nil || strings.TrimSpace(u.ID) == "" {
			return "", "", false, ErrUserNotFound
		}
		userID = strings.TrimSpace(u.ID)
		created = true
	default:
		return "", "", false, err
	}

	reservedUserID, reservedTenantID, _, reserveErr := s.ReserveAccount(ctx, slug)
	if reserveErr != nil {
		return "", "", false, reserveErr
	}
	if strings.TrimSpace(userID) == "" {
		userID = strings.TrimSpace(reservedUserID)
	}
	tenantID = strings.TrimSpace(reservedTenantID)
	return strings.TrimSpace(userID), strings.TrimSpace(tenantID), created, nil
}

// ClaimUserNamespace ensures a slug resolves to a non-reserved user namespace.
//
// Behavior:
//   - If no same-slug user exists, creates one (and a personal tenant) and marks it claimed.
//   - Clears user reserved metadata and any restricted-name marker for the slug.
//   - Forces the user's personal tenant namespace state to registered_tenant when present.
//   - If a same-slug non-personal tenant exists, returns ErrInvalidOwnerNamespaceTransition.
func (s *Service) ClaimUserNamespace(ctx context.Context, slug string) (userID, tenantID string, created bool, err error) {
	if err := s.requirePG(); err != nil {
		return "", "", false, err
	}
	slug = normalizeReservedSlug(slug)
	if err := validateTenantSlug(slug); err != nil {
		return "", "", false, err
	}

	if tenant, err := s.ResolveTenantBySlug(ctx, slug); err == nil && tenant != nil {
		if !tenant.IsPersonal {
			return "", "", false, ErrInvalidOwnerNamespaceTransition
		}
	} else if err != nil && !errors.Is(err, ErrTenantNotFound) {
		return "", "", false, err
	}

	switch id, _, err := s.ResolveUserBySlug(ctx, slug); {
	case err == nil:
		userID = strings.TrimSpace(id)
	case errors.Is(err, ErrUserNotFound):
		state, stateErr := s.GetOwnerNamespaceStateBySlug(ctx, slug)
		if stateErr == nil && state == OwnerNamespaceStateRestrictedName {
			if _, _, unrestrictErr := s.UnrestrictOwnerNamespaceSlugs(ctx, []string{slug}); unrestrictErr != nil {
				return "", "", false, unrestrictErr
			}
		} else if stateErr != nil && !errors.Is(stateErr, ErrOwnerNamespaceNotFound) {
			return "", "", false, stateErr
		}

		u, createErr := s.CreateUser(ctx, "", slug)
		if createErr != nil {
			return "", "", false, createErr
		}
		if u == nil || strings.TrimSpace(u.ID) == "" {
			return "", "", false, ErrUserNotFound
		}
		userID = strings.TrimSpace(u.ID)
		created = true
	default:
		return "", "", false, err
	}

	if err := s.PatchUserMetadata(ctx, userID, map[string]any{"reserved": false}); err != nil {
		return "", "", false, err
	}
	if _, _, err := s.UnrestrictOwnerNamespaceSlugs(ctx, []string{slug}); err != nil {
		return "", "", false, err
	}
	if personalTenant, err := s.GetPersonalTenantForUser(ctx, userID); err == nil && personalTenant != nil && strings.TrimSpace(personalTenant.ID) != "" {
		if err := s.SetTenantNamespaceState(ctx, strings.TrimSpace(personalTenant.ID), OwnerNamespaceStateRegistered); err != nil {
			return "", "", false, err
		}
		tenantID = strings.TrimSpace(personalTenant.ID)
	} else if err != nil && !errors.Is(err, ErrPersonalTenantNotFound) {
		return "", "", false, err
	}

	return strings.TrimSpace(userID), strings.TrimSpace(tenantID), created, nil
}

func (s *Service) countActiveTenantOwners(ctx context.Context, tenantID string) (int, error) {
	if err := s.requirePG(); err != nil {
		return 0, err
	}
	if strings.TrimSpace(tenantID) == "" {
		return 0, fmt.Errorf("invalid_tenant")
	}
	n, err := s.q.TenantRoleMemberCount(ctx, db.TenantRoleMemberCountParams{TenantID: tenantID, Role: tenantOwnerRole})
	if err != nil {
		return 0, err
	}
	return int(n), nil
}
