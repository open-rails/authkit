package core

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type OwnerNamespaceLookupStatus string

const (
	OwnerNamespaceStatusRegisteredUser         OwnerNamespaceLookupStatus = "registered_user"
	OwnerNamespaceStatusRegisteredTenant       OwnerNamespaceLookupStatus = "registered_tenant"
	OwnerNamespaceStatusParkedUser             OwnerNamespaceLookupStatus = "parked_user"
	OwnerNamespaceStatusParkedTenant           OwnerNamespaceLookupStatus = "parked_tenant"
	OwnerNamespaceStatusRestrictedName         OwnerNamespaceLookupStatus = "restricted_name"
	OwnerNamespaceStatusRenamedUser            OwnerNamespaceLookupStatus = "renamed_user"
	OwnerNamespaceStatusRenamedTenant          OwnerNamespaceLookupStatus = "renamed_tenant"
	OwnerNamespaceStatusHeldByDeletedUser      OwnerNamespaceLookupStatus = "held_by_deleted_user"
	OwnerNamespaceStatusHeldByDeletedTenant    OwnerNamespaceLookupStatus = "held_by_deleted_tenant"
	OwnerNamespaceStatusHeldByRecentUserRename OwnerNamespaceLookupStatus = "held_by_recent_user_rename"
	OwnerNamespaceStatusHeldByRecentOrgRename  OwnerNamespaceLookupStatus = "held_by_recent_tenant_rename"
	OwnerNamespaceStatusUnregistered           OwnerNamespaceLookupStatus = "unregistered"
)

type OwnerNamespaceLookupUser struct {
	ID       string
	Username string
}

type OwnerNamespaceLookupTenant struct {
	ID          string
	Slug        string
	IsPersonal  bool
	OwnerUserID string
	State       OwnerNamespaceState
}

type OwnerNamespaceLookup struct {
	RequestedSlug string
	CanonicalSlug string
	Status        OwnerNamespaceLookupStatus
	Claimable     bool
	Exists        bool
	EntityKind    string
	Renamed       bool
	HoldUntil     *time.Time
	User          *OwnerNamespaceLookupUser
	Tenant        *OwnerNamespaceLookupTenant
}

type ownerNamespaceCurrentUser struct {
	id       string
	username string
	deleted  bool
	reserved bool
}

type ownerNamespaceCurrentTenant struct {
	id          string
	slug        string
	isPersonal  bool
	ownerUserID string
	deleted     bool
	state       OwnerNamespaceState
}

// LookupOwnerNamespace returns one canonical availability/routing view for an
// owner slug. It intentionally uses the same sources as both owner resolution
// and owner-slug availability so callers can distinguish "not registered" from
// "not resolvable but still held".
func (s *Service) LookupOwnerNamespace(ctx context.Context, slug string) (*OwnerNamespaceLookup, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	requested := strings.ToLower(strings.TrimSpace(slug))
	if err := validateTenantSlug(requested); err != nil {
		return nil, err
	}

	out := &OwnerNamespaceLookup{
		RequestedSlug: requested,
		CanonicalSlug: requested,
		Status:        OwnerNamespaceStatusUnregistered,
		Claimable:     true,
		EntityKind:    "none",
	}

	user, userErr := s.lookupOwnerNamespaceCurrentUser(ctx, requested)
	if userErr != nil {
		return nil, userErr
	}
	tenant, orgErr := s.lookupOwnerNamespaceCurrentTenant(ctx, requested)
	if orgErr != nil {
		return nil, orgErr
	}

	if user != nil || tenant != nil {
		return s.ownerNamespaceLookupFromCurrent(out, user, tenant), nil
	}

	restricted, err := s.ownerNamespaceRestrictedNameExists(ctx, requested)
	if err != nil {
		return nil, err
	}
	if restricted {
		out.Status = OwnerNamespaceStatusRestrictedName
		out.Claimable = false
		return out, nil
	}

	if renamed, err := s.lookupOwnerNamespaceUserRename(ctx, requested); err != nil {
		return nil, err
	} else if renamed != nil {
		return renamed, nil
	}

	if renamed, err := s.lookupOwnerNamespaceOrgRename(ctx, requested); err != nil {
		return nil, err
	} else if renamed != nil {
		return renamed, nil
	}

	return out, nil
}

func (s *Service) ownerNamespaceLookupFromCurrent(out *OwnerNamespaceLookup, user *ownerNamespaceCurrentUser, tenant *ownerNamespaceCurrentTenant) *OwnerNamespaceLookup {
	out.Claimable = false

	hasLiveUser := user != nil && !user.deleted
	hasLiveTenant := tenant != nil && !tenant.deleted
	hasDeletedUser := user != nil && user.deleted
	hasDeletedTenant := tenant != nil && tenant.deleted

	switch {
	case hasLiveUser && hasLiveTenant:
		out.Exists = true
		out.EntityKind = "tenant_and_user"
	case hasLiveUser:
		out.Exists = true
		out.EntityKind = "user"
	case hasLiveTenant:
		out.Exists = true
		out.EntityKind = "tenant"
	default:
		out.Exists = false
		out.EntityKind = "none"
	}

	if hasLiveTenant {
		state := tenant.state
		if state == "" {
			state = OwnerNamespaceStateRegistered
		}
		out.Tenant = &OwnerNamespaceLookupTenant{
			ID:          strings.TrimSpace(tenant.id),
			Slug:        strings.TrimSpace(tenant.slug),
			IsPersonal:  tenant.isPersonal,
			OwnerUserID: strings.TrimSpace(tenant.ownerUserID),
			State:       state,
		}
		out.CanonicalSlug = strings.TrimSpace(tenant.slug)
		if state == OwnerNamespaceStateParkedTenant {
			out.Status = OwnerNamespaceStatusParkedTenant
		} else {
			out.Status = OwnerNamespaceStatusRegisteredTenant
		}
	}
	if hasLiveUser {
		out.User = &OwnerNamespaceLookupUser{
			ID:       strings.TrimSpace(user.id),
			Username: strings.TrimSpace(user.username),
		}
		out.CanonicalSlug = strings.TrimSpace(user.username)
		if user.reserved {
			out.Status = OwnerNamespaceStatusParkedUser
		} else {
			out.Status = OwnerNamespaceStatusRegisteredUser
		}
	}
	if !hasLiveUser && !hasLiveTenant {
		if hasDeletedUser {
			out.Status = OwnerNamespaceStatusHeldByDeletedUser
			out.CanonicalSlug = strings.TrimSpace(user.username)
			return out
		}
		if hasDeletedTenant {
			out.Status = OwnerNamespaceStatusHeldByDeletedTenant
			out.CanonicalSlug = strings.TrimSpace(tenant.slug)
			return out
		}
	}
	if out.Status == "" {
		out.Status = OwnerNamespaceStatusUnregistered
		out.Claimable = true
	}
	return out
}

func (s *Service) lookupOwnerNamespaceCurrentUser(ctx context.Context, slug string) (*ownerNamespaceCurrentUser, error) {
	var user ownerNamespaceCurrentUser
	if err := s.pg.QueryRow(ctx, `
		SELECT id::text,
		       username::text,
		       deleted_at IS NOT NULL,
		       CASE
		         WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
		         THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
		         ELSE false
		       END
		FROM profiles.users
		WHERE username=$1
	`, slug).Scan(&user.id, &user.username, &user.deleted, &user.reserved); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (s *Service) lookupOwnerNamespaceCurrentTenant(ctx context.Context, slug string) (*ownerNamespaceCurrentTenant, error) {
	var tenant ownerNamespaceCurrentTenant
	var stateRaw string
	var reserved bool
	if err := s.pg.QueryRow(ctx, `
		SELECT id::text,
		       slug,
		       is_personal,
		       COALESCE(owner_user_id::text, ''),
		       deleted_at IS NOT NULL,
		       COALESCE(COALESCE(metadata, '{}'::jsonb)->>'namespace_state', '') AS state_raw,
		       CASE
		         WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
		         THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
		         ELSE false
		       END AS reserved
		FROM profiles.tenants
		WHERE slug=$1
	`, slug).Scan(&tenant.id, &tenant.slug, &tenant.isPersonal, &tenant.ownerUserID, &tenant.deleted, &stateRaw, &reserved); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	tenant.state = normalizeOwnerNamespaceState(OwnerNamespaceState(stateRaw))
	if tenant.state == "" {
		if reserved {
			tenant.state = OwnerNamespaceStateParkedTenant
		} else {
			tenant.state = OwnerNamespaceStateRegistered
		}
	}
	return &tenant, nil
}

func (s *Service) ownerNamespaceRestrictedNameExists(ctx context.Context, slug string) (bool, error) {
	var exists bool
	if err := s.pg.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM profiles.owner_reserved_names WHERE slug=$1)
	`, slug).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

func (s *Service) lookupOwnerNamespaceUserRename(ctx context.Context, slug string) (*OwnerNamespaceLookup, error) {
	var userID, username string
	var deleted bool
	var renamedAt time.Time
	if err := s.pg.QueryRow(ctx, `
		SELECT u.id::text, u.username::text, u.deleted_at IS NOT NULL, r.renamed_at
		FROM profiles.user_renames r
		JOIN profiles.users u ON u.id=r.user_id
		WHERE r.from_slug=$1
		ORDER BY r.renamed_at DESC
		LIMIT 1
	`, slug).Scan(&userID, &username, &deleted, &renamedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return ownerNamespaceLookupFromRename(slug, username, userID, renamedAt, deleted, true), nil
}

func (s *Service) lookupOwnerNamespaceOrgRename(ctx context.Context, slug string) (*OwnerNamespaceLookup, error) {
	var tenantID, tenantSlug string
	var isPersonal bool
	var ownerUserID string
	var deleted bool
	var renamedAt time.Time
	if err := s.pg.QueryRow(ctx, `
		SELECT o.id::text, o.slug, o.is_personal, COALESCE(o.owner_user_id::text, ''), o.deleted_at IS NOT NULL, r.renamed_at
		FROM profiles.tenant_renames r
		JOIN profiles.tenants o ON o.id=r.tenant_id
		WHERE r.from_slug=$1
		ORDER BY r.renamed_at DESC
		LIMIT 1
	`, slug).Scan(&tenantID, &tenantSlug, &isPersonal, &ownerUserID, &deleted, &renamedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	out := ownerNamespaceLookupFromRename(slug, tenantSlug, tenantID, renamedAt, deleted, false)
	if !deleted {
		out.Tenant = &OwnerNamespaceLookupTenant{
			ID:          strings.TrimSpace(tenantID),
			Slug:        strings.TrimSpace(tenantSlug),
			IsPersonal:  isPersonal,
			OwnerUserID: strings.TrimSpace(ownerUserID),
			State:       OwnerNamespaceStateRegistered,
		}
	}
	return out, nil
}

func ownerNamespaceLookupFromRename(requested, canonical, ownerID string, renamedAt time.Time, deleted bool, user bool) *OwnerNamespaceLookup {
	holdUntil := renamedAt.UTC().Add(renameReuseHold)
	claimable := time.Now().UTC().After(holdUntil)
	out := &OwnerNamespaceLookup{
		RequestedSlug: strings.TrimSpace(requested),
		CanonicalSlug: strings.TrimSpace(canonical),
		Status:        OwnerNamespaceStatusUnregistered,
		Claimable:     claimable,
		Exists:        false,
		EntityKind:    "none",
		Renamed:       !deleted,
		HoldUntil:     &holdUntil,
	}
	if user {
		if deleted {
			if claimable {
				out.CanonicalSlug = strings.TrimSpace(requested)
				out.HoldUntil = nil
			} else {
				out.Status = OwnerNamespaceStatusHeldByRecentUserRename
			}
			return out
		}
		out.Status = OwnerNamespaceStatusRenamedUser
		out.Exists = true
		out.EntityKind = "user"
		out.User = &OwnerNamespaceLookupUser{ID: strings.TrimSpace(ownerID), Username: strings.TrimSpace(canonical)}
		return out
	}
	if deleted {
		if claimable {
			out.CanonicalSlug = strings.TrimSpace(requested)
			out.HoldUntil = nil
		} else {
			out.Status = OwnerNamespaceStatusHeldByRecentOrgRename
		}
		return out
	}
	out.Status = OwnerNamespaceStatusRenamedTenant
	out.Exists = true
	out.EntityKind = "tenant"
	return out
}
