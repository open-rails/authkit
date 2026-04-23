package core

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

type OwnerNamespaceState string

const (
	OwnerNamespaceStateRestrictedName OwnerNamespaceState = "restricted_name"
	OwnerNamespaceStateParkedOrg      OwnerNamespaceState = "parked_org"
	OwnerNamespaceStateRegistered     OwnerNamespaceState = "registered_org"
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
	case OwnerNamespaceStateParkedOrg:
		return OwnerNamespaceStateParkedOrg
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
	var exists bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM profiles.owner_reserved_names WHERE lower(slug)=lower($1)
		)
	`, slug).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

func (s *Service) upsertOwnerReservedNameTx(ctx context.Context, tx pgx.Tx, slug string) error {
	if tx == nil {
		return fmt.Errorf("tx required")
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO profiles.owner_reserved_names (slug)
		VALUES ($1)
		ON CONFLICT (slug) DO UPDATE SET updated_at=now()
	`, slug)
	return err
}

func (s *Service) deleteOwnerReservedNameTx(ctx context.Context, tx pgx.Tx, slug string) error {
	if tx == nil {
		return fmt.Errorf("tx required")
	}
	_, err := tx.Exec(ctx, `DELETE FROM profiles.owner_reserved_names WHERE lower(slug)=lower($1)`, slug)
	return err
}

func (s *Service) ownerSlugConflictExistsTx(ctx context.Context, tx pgx.Tx, slug string) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("tx required")
	}
	var exists bool
	if err := tx.QueryRow(ctx, `
		SELECT (
			EXISTS(SELECT 1 FROM profiles.users u WHERE lower(u.username::text)=lower($1) AND u.deleted_at IS NULL)
			OR EXISTS(SELECT 1 FROM profiles.user_slug_aliases a WHERE lower(a.slug::text)=lower($1) AND a.deleted_at IS NULL)
			OR EXISTS(SELECT 1 FROM profiles.orgs o WHERE o.slug=$1 AND o.deleted_at IS NULL)
			OR EXISTS(SELECT 1 FROM profiles.org_slug_aliases a WHERE a.slug=$1 AND a.deleted_at IS NULL)
		)
	`, slug).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

func (s *Service) IsUserReserved(ctx context.Context, userID string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	if strings.TrimSpace(userID) == "" {
		return false, fmt.Errorf("invalid_user")
	}
	var reserved bool
	if err := s.pg.QueryRow(ctx, `
		SELECT `+s.reservedUserFlagExpr()+`
		FROM profiles.users
		WHERE id=$1::uuid
	`, userID).Scan(&reserved); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrUserNotFound
		}
		return false, err
	}
	return reserved, nil
}

func (s *Service) GetOrgNamespaceState(ctx context.Context, orgID string) (OwnerNamespaceState, error) {
	if err := s.requirePG(); err != nil {
		return "", err
	}
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("invalid_org")
	}
	var stateRaw string
	var reserved bool
	if err := s.pg.QueryRow(ctx, `
		SELECT COALESCE(COALESCE(metadata, '{}'::jsonb)->>'namespace_state', '') AS state_raw,
		       CASE
		         WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
		         THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
		         ELSE false
		       END AS reserved
		FROM profiles.orgs
		WHERE id=$1::uuid AND deleted_at IS NULL
	`, orgID).Scan(&stateRaw, &reserved); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrOrgNotFound
		}
		return "", err
	}
	state := normalizeOwnerNamespaceState(OwnerNamespaceState(stateRaw))
	if state != "" {
		return state, nil
	}
	if reserved {
		return OwnerNamespaceStateParkedOrg, nil
	}
	return OwnerNamespaceStateRegistered, nil
}

func (s *Service) setOrgNamespaceStateTx(ctx context.Context, tx pgx.Tx, orgID string, state OwnerNamespaceState) error {
	if tx == nil {
		return fmt.Errorf("tx required")
	}
	state = normalizeOwnerNamespaceState(state)
	if err := validateOwnerNamespaceState(state); err != nil {
		return err
	}
	reserved := state == OwnerNamespaceStateParkedOrg
	tag, err := tx.Exec(ctx, `
		UPDATE profiles.orgs
		SET metadata=jsonb_set(
				jsonb_set(COALESCE(metadata, '{}'::jsonb), '{namespace_state}', to_jsonb($2::text), true),
				'{reserved}', to_jsonb($3::boolean), true
			),
			updated_at=now()
		WHERE id=$1::uuid AND deleted_at IS NULL
	`, orgID, string(state), reserved)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrOrgNotFound
	}
	return nil
}

func (s *Service) SetOrgNamespaceState(ctx context.Context, orgID string, state OwnerNamespaceState) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	if strings.TrimSpace(orgID) == "" {
		return fmt.Errorf("invalid_org")
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.setOrgNamespaceStateTx(ctx, tx, orgID, state); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) GetOwnerNamespaceStateBySlug(ctx context.Context, slug string) (OwnerNamespaceState, error) {
	if err := s.requirePG(); err != nil {
		return "", err
	}
	slug = normalizeReservedSlug(slug)
	if err := validateOrgSlug(slug); err != nil {
		return "", err
	}
	var exists bool
	if err := s.pg.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM profiles.owner_reserved_names WHERE lower(slug)=lower($1))
	`, slug).Scan(&exists); err != nil {
		return "", err
	}
	if exists {
		return OwnerNamespaceStateRestrictedName, nil
	}
	org, err := s.ResolveOrgBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, ErrOrgNotFound) {
			return "", ErrOwnerNamespaceNotFound
		}
		return "", err
	}
	state, err := s.GetOrgNamespaceState(ctx, org.ID)
	if err != nil {
		return "", err
	}
	return state, nil
}

// ParkOrgNamespace parks `slug` as a parked_org. Works whether or not the slug
// is currently in owner_reserved_names — any caller-supplied slug is parkable,
// even bootstrap-reserved names like 'root' or 'admin'. If a reserved-name row
// exists it's deleted as part of the transaction. Internal-library API only —
// not exposed publicly.
func (s *Service) ParkOrgNamespace(ctx context.Context, slug string) (orgID string, created bool, err error) {
	if err := s.requirePG(); err != nil {
		return "", false, err
	}
	slug = normalizeReservedSlug(slug)
	if err := validateOrgSlug(slug); err != nil {
		return "", false, err
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var existingID string
	var isPersonal bool
	err = tx.QueryRow(ctx, `
		SELECT id::text, is_personal
		FROM profiles.orgs
		WHERE slug=$1 AND deleted_at IS NULL
	`, slug).Scan(&existingID, &isPersonal)
	switch {
	case err == nil:
		if isPersonal {
			return "", false, ErrInvalidOwnerNamespaceTransition
		}
		if err := s.setOrgNamespaceStateTx(ctx, tx, existingID, OwnerNamespaceStateParkedOrg); err != nil {
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
	// Explicit ::text cast on $2 — pgx can't infer the type when the parameter
	// is only used inside jsonb_build_object.
	if err := tx.QueryRow(ctx, `
		INSERT INTO profiles.orgs (slug, metadata)
		VALUES ($1, jsonb_build_object('namespace_state', $2::text, 'reserved', to_jsonb(true)))
		RETURNING id::text
	`, slug, string(OwnerNamespaceStateParkedOrg)).Scan(&orgID); err != nil {
		return "", false, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO profiles.org_roles (org_id, role)
		VALUES ($1::uuid, 'owner'), ($1::uuid, 'member')
		ON CONFLICT (org_id, role) DO NOTHING
	`, orgID); err != nil {
		return "", false, err
	}
	if err := s.deleteOwnerReservedNameTx(ctx, tx, slug); err != nil {
		return "", false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", false, err
	}
	return strings.TrimSpace(orgID), true, nil
}

func (s *Service) PromoteParkedOrgToRegistered(ctx context.Context, slug, ownerUserID string) (orgID string, err error) {
	if err := s.requirePG(); err != nil {
		return "", err
	}
	slug = normalizeReservedSlug(slug)
	if err := validateOrgSlug(slug); err != nil {
		return "", err
	}
	org, err := s.ResolveOrgBySlug(ctx, slug)
	if err != nil {
		return "", err
	}
	state, err := s.GetOrgNamespaceState(ctx, org.ID)
	if err != nil {
		return "", err
	}
	if state != OwnerNamespaceStateParkedOrg {
		return "", ErrInvalidOwnerNamespaceTransition
	}
	return s.claimParkedOrgToRegistered(ctx, org, ownerUserID)
}

// PromoteReservedNameToRegistered supports direct handoff in one operation:
//
//	restricted_name -> parked_org -> registered_org
//
// It is idempotent for already-registered orgs and optionally ensures owner membership.
func (s *Service) PromoteReservedNameToRegistered(ctx context.Context, slug, ownerUserID string) (orgID string, created bool, err error) {
	if err := s.requirePG(); err != nil {
		return "", false, err
	}
	slug = normalizeReservedSlug(slug)
	if err := validateOrgSlug(slug); err != nil {
		return "", false, err
	}
	state, err := s.GetOwnerNamespaceStateBySlug(ctx, slug)
	if err != nil {
		return "", false, err
	}
	switch state {
	case OwnerNamespaceStateRestrictedName:
		orgID, created, err = s.ParkOrgNamespace(ctx, slug)
		if err != nil {
			return "", false, err
		}
		registeredID, err := s.PromoteParkedOrgToRegistered(ctx, slug, ownerUserID)
		if err != nil {
			return "", false, err
		}
		return strings.TrimSpace(registeredID), created, nil
	case OwnerNamespaceStateParkedOrg:
		registeredID, err := s.PromoteParkedOrgToRegistered(ctx, slug, ownerUserID)
		if err != nil {
			return "", false, err
		}
		return strings.TrimSpace(registeredID), false, nil
	case OwnerNamespaceStateRegistered:
		org, err := s.ResolveOrgBySlug(ctx, slug)
		if err != nil {
			return "", false, err
		}
		ownerUserID = strings.TrimSpace(ownerUserID)
		if ownerUserID == "" {
			ownerCount, err := s.countActiveOrgOwners(ctx, strings.TrimSpace(org.ID))
			if err != nil {
				return "", false, err
			}
			if ownerCount < 1 {
				return "", false, ErrOwnerMembershipRequired
			}
			return strings.TrimSpace(org.ID), false, nil
		}
		if err := s.AddMember(ctx, org.Slug, ownerUserID); err != nil {
			return "", false, err
		}
		if err := s.AssignRole(ctx, org.Slug, ownerUserID, orgOwnerRole); err != nil {
			return "", false, err
		}
		ownerCount, err := s.countActiveOrgOwners(ctx, strings.TrimSpace(org.ID))
		if err != nil {
			return "", false, err
		}
		if ownerCount < 1 {
			return "", false, ErrOwnerMembershipRequired
		}
		return strings.TrimSpace(org.ID), false, nil
	default:
		return "", false, ErrInvalidOwnerNamespaceTransition
	}
}

func (s *Service) claimParkedOrgToRegistered(ctx context.Context, org *Org, ownerUserID string) (orgID string, err error) {
	if org == nil || strings.TrimSpace(org.ID) == "" {
		return "", ErrOrgNotFound
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
	ownerCount, err := s.countActiveOrgOwners(ctx, strings.TrimSpace(org.ID))
	if err != nil {
		return "", err
	}
	if ownerCount > 0 {
		return "", ErrOwnerNamespaceAlreadyClaimed
	}
	if err := s.AddMember(ctx, org.Slug, ownerUserID); err != nil {
		return "", err
	}
	if err := s.AssignRole(ctx, org.Slug, ownerUserID, orgOwnerRole); err != nil {
		return "", err
	}
	ownerCount, err = s.countActiveOrgOwners(ctx, strings.TrimSpace(org.ID))
	if err != nil {
		return "", err
	}
	if ownerCount < 1 {
		return "", ErrOwnerMembershipRequired
	}
	if err := s.SetOrgNamespaceState(ctx, org.ID, OwnerNamespaceStateRegistered); err != nil {
		return "", err
	}
	_, _ = s.pg.Exec(ctx, `DELETE FROM profiles.owner_reserved_names WHERE lower(slug)=lower($1)`, org.Slug)
	return strings.TrimSpace(org.ID), nil
}

func normalizeOwnerNamespaceSlugs(raw []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		slug := normalizeReservedSlug(item)
		if slug == "" {
			continue
		}
		if err := validateOrgSlug(slug); err != nil {
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
// It is an admin operation separate from park/claim org lifecycle transitions.
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
		tag, err := tx.Exec(ctx, `DELETE FROM profiles.owner_reserved_names WHERE lower(slug)=lower($1)`, slug)
		if err != nil {
			return nil, nil, err
		}
		if tag.RowsAffected() == 0 {
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

// ClaimOrgNamespace claims org ownership for a specific existing user.
//
// Rules:
//   - parked_org -> registered_org + owner membership assignment
//   - already-registered orgs return ErrOwnerNamespaceAlreadyClaimed
//   - restricted_name (or missing namespace) creates the org if needed, then claims it
//   - owner user must exist and not be soft-deleted
func (s *Service) ClaimOrgNamespace(ctx context.Context, slug, ownerUserID string) (orgID string, created bool, err error) {
	if err := s.requirePG(); err != nil {
		return "", false, err
	}
	slug = normalizeReservedSlug(slug)
	if err := validateOrgSlug(slug); err != nil {
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
			org, createErr := s.CreateOrg(ctx, slug)
			if createErr != nil {
				return "", false, createErr
			}
			claimedID, claimErr := s.claimParkedOrgToRegistered(ctx, org, ownerUserID)
			if claimErr != nil {
				return "", false, claimErr
			}
			return claimedID, true, nil
		}
		return "", false, err
	}

	switch state {
	case OwnerNamespaceStateParkedOrg:
		org, resolveErr := s.ResolveOrgBySlug(ctx, slug)
		if resolveErr != nil {
			return "", false, resolveErr
		}
		claimedID, claimErr := s.claimParkedOrgToRegistered(ctx, org, ownerUserID)
		if claimErr != nil {
			return "", false, claimErr
		}
		return claimedID, false, nil
	case OwnerNamespaceStateRestrictedName:
		org, resolveErr := s.ResolveOrgBySlug(ctx, slug)
		switch {
		case resolveErr == nil:
			ownerCount, countErr := s.countActiveOrgOwners(ctx, strings.TrimSpace(org.ID))
			if countErr != nil {
				return "", false, countErr
			}
			if ownerCount > 0 {
				return "", false, ErrOwnerNamespaceAlreadyClaimed
			}
		case errors.Is(resolveErr, ErrOrgNotFound):
		default:
			return "", false, resolveErr
		}

		parkedID, parkedCreated, parkErr := s.ParkOrgNamespace(ctx, slug)
		if parkErr != nil {
			return "", false, parkErr
		}
		parkedOrg, resolveErr := s.ResolveOrgBySlug(ctx, slug)
		if resolveErr != nil {
			return "", false, resolveErr
		}
		claimedID, claimErr := s.claimParkedOrgToRegistered(ctx, parkedOrg, ownerUserID)
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
//   - If no same-slug user exists, creates a placeholder user (and personal org), then parks it.
//   - If a same-slug non-personal org exists, returns ErrInvalidOwnerNamespaceTransition.
//   - Requires the slug to be valid and available for user ownership semantics.
func (s *Service) ParkUserNamespace(ctx context.Context, slug string) (userID, orgID string, created bool, err error) {
	if err := s.requirePG(); err != nil {
		return "", "", false, err
	}
	slug = normalizeReservedSlug(slug)
	if err := validateOrgSlug(slug); err != nil {
		return "", "", false, err
	}

	if org, err := s.ResolveOrgBySlug(ctx, slug); err == nil && org != nil {
		if !org.IsPersonal {
			return "", "", false, ErrInvalidOwnerNamespaceTransition
		}
	} else if err != nil && !errors.Is(err, ErrOrgNotFound) {
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

	reservedUserID, reservedOrgID, _, reserveErr := s.ReserveAccount(ctx, slug)
	if reserveErr != nil {
		return "", "", false, reserveErr
	}
	if strings.TrimSpace(userID) == "" {
		userID = strings.TrimSpace(reservedUserID)
	}
	orgID = strings.TrimSpace(reservedOrgID)
	return strings.TrimSpace(userID), strings.TrimSpace(orgID), created, nil
}

// ClaimUserNamespace ensures a slug resolves to a non-reserved user namespace.
//
// Behavior:
//   - If no same-slug user exists, creates one (and a personal org) and marks it claimed.
//   - Clears user reserved metadata and any restricted-name marker for the slug.
//   - Forces the user's personal org namespace state to registered_org when present.
//   - If a same-slug non-personal org exists, returns ErrInvalidOwnerNamespaceTransition.
func (s *Service) ClaimUserNamespace(ctx context.Context, slug string) (userID, orgID string, created bool, err error) {
	if err := s.requirePG(); err != nil {
		return "", "", false, err
	}
	slug = normalizeReservedSlug(slug)
	if err := validateOrgSlug(slug); err != nil {
		return "", "", false, err
	}

	if org, err := s.ResolveOrgBySlug(ctx, slug); err == nil && org != nil {
		if !org.IsPersonal {
			return "", "", false, ErrInvalidOwnerNamespaceTransition
		}
	} else if err != nil && !errors.Is(err, ErrOrgNotFound) {
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
	if personalOrg, err := s.GetPersonalOrgForUser(ctx, userID); err == nil && personalOrg != nil && strings.TrimSpace(personalOrg.ID) != "" {
		if err := s.SetOrgNamespaceState(ctx, strings.TrimSpace(personalOrg.ID), OwnerNamespaceStateRegistered); err != nil {
			return "", "", false, err
		}
		orgID = strings.TrimSpace(personalOrg.ID)
	} else if err != nil && !errors.Is(err, ErrPersonalOrgNotFound) {
		return "", "", false, err
	}

	return strings.TrimSpace(userID), strings.TrimSpace(orgID), created, nil
}

func (s *Service) countActiveOrgOwners(ctx context.Context, orgID string) (int, error) {
	if err := s.requirePG(); err != nil {
		return 0, err
	}
	if strings.TrimSpace(orgID) == "" {
		return 0, fmt.Errorf("invalid_org")
	}
	var n int
	if err := s.pg.QueryRow(ctx, `
		SELECT COUNT(DISTINCT r.user_id)::int
		FROM profiles.org_member_roles r
		JOIN profiles.org_members m
		  ON m.org_id=r.org_id
		 AND m.user_id=r.user_id
		WHERE r.org_id=$1::uuid
		  AND r.role='owner'
		  AND m.deleted_at IS NULL
	`, orgID).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}
