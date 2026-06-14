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
	OwnerNamespaceStatusRegisteredOrg          OwnerNamespaceLookupStatus = "registered_tenant"
	OwnerNamespaceStatusParkedUser             OwnerNamespaceLookupStatus = "parked_user"
	OwnerNamespaceStatusParkedOrg              OwnerNamespaceLookupStatus = "parked_tenant"
	OwnerNamespaceStatusRestrictedName         OwnerNamespaceLookupStatus = "restricted_name"
	OwnerNamespaceStatusRenamedUser            OwnerNamespaceLookupStatus = "renamed_user"
	OwnerNamespaceStatusRenamedOrg             OwnerNamespaceLookupStatus = "renamed_org"
	OwnerNamespaceStatusHeldByDeletedUser      OwnerNamespaceLookupStatus = "held_by_deleted_user"
	OwnerNamespaceStatusHeldByDeletedOrg       OwnerNamespaceLookupStatus = "held_by_deleted_org"
	OwnerNamespaceStatusHeldByRecentUserRename OwnerNamespaceLookupStatus = "held_by_recent_user_rename"
	OwnerNamespaceStatusHeldByRecentOrgRename  OwnerNamespaceLookupStatus = "held_by_recent_org_rename"
	OwnerNamespaceStatusUnregistered           OwnerNamespaceLookupStatus = "unregistered"
)

type OwnerNamespaceLookupUser struct {
	ID       string
	Username string
}

type OwnerNamespaceLookupOrg struct {
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
	Org           *OwnerNamespaceLookupOrg
}

type ownerNamespaceCurrentUser struct {
	id       string
	username string
	deleted  bool
	reserved bool
}

type ownerNamespaceCurrentOrg struct {
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
	if err := validateOrgSlug(requested); err != nil {
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
	org, orgErr := s.lookupOwnerNamespaceCurrentOrg(ctx, requested)
	if orgErr != nil {
		return nil, orgErr
	}

	if user != nil || org != nil {
		return s.ownerNamespaceLookupFromCurrent(out, user, org), nil
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

func (s *Service) ownerNamespaceLookupFromCurrent(out *OwnerNamespaceLookup, user *ownerNamespaceCurrentUser, org *ownerNamespaceCurrentOrg) *OwnerNamespaceLookup {
	out.Claimable = false

	hasLiveUser := user != nil && !user.deleted
	hasLiveOrg := org != nil && !org.deleted
	hasDeletedUser := user != nil && user.deleted
	hasDeletedOrg := org != nil && org.deleted

	switch {
	case hasLiveUser && hasLiveOrg:
		out.Exists = true
		out.EntityKind = "org_and_user"
	case hasLiveUser:
		out.Exists = true
		out.EntityKind = "user"
	case hasLiveOrg:
		out.Exists = true
		out.EntityKind = "org"
	default:
		out.Exists = false
		out.EntityKind = "none"
	}

	if hasLiveOrg {
		state := org.state
		if state == "" {
			state = OwnerNamespaceStateRegistered
		}
		out.Org = &OwnerNamespaceLookupOrg{
			ID:          strings.TrimSpace(org.id),
			Slug:        strings.TrimSpace(org.slug),
			IsPersonal:  org.isPersonal,
			OwnerUserID: strings.TrimSpace(org.ownerUserID),
			State:       state,
		}
		out.CanonicalSlug = strings.TrimSpace(org.slug)
		if state == OwnerNamespaceStateParkedOrg {
			out.Status = OwnerNamespaceStatusParkedOrg
		} else {
			out.Status = OwnerNamespaceStatusRegisteredOrg
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
	if !hasLiveUser && !hasLiveOrg {
		if hasDeletedUser {
			out.Status = OwnerNamespaceStatusHeldByDeletedUser
			out.CanonicalSlug = strings.TrimSpace(user.username)
			return out
		}
		if hasDeletedOrg {
			out.Status = OwnerNamespaceStatusHeldByDeletedOrg
			out.CanonicalSlug = strings.TrimSpace(org.slug)
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
	row, err := s.q.NamespaceUserBySlug(ctx, &slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &ownerNamespaceCurrentUser{id: row.ID, username: row.Username, deleted: row.Deleted, reserved: row.Reserved}, nil
}

func (s *Service) lookupOwnerNamespaceCurrentOrg(ctx context.Context, slug string) (*ownerNamespaceCurrentOrg, error) {
	row, err := s.q.NamespaceOrgBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	org := ownerNamespaceCurrentOrg{
		id:          row.ID,
		slug:        row.Slug,
		isPersonal:  row.IsPersonal,
		ownerUserID: row.OwnerUserID,
		deleted:     row.Deleted,
	}
	org.state = normalizeOwnerNamespaceState(OwnerNamespaceState(row.StateRaw))
	if org.state == "" {
		if row.Reserved {
			org.state = OwnerNamespaceStateParkedOrg
		} else {
			org.state = OwnerNamespaceStateRegistered
		}
	}
	return &org, nil
}

func (s *Service) ownerNamespaceRestrictedNameExists(ctx context.Context, slug string) (bool, error) {
	return s.q.OwnerReservedNameExists(ctx, slug)
}

func (s *Service) lookupOwnerNamespaceUserRename(ctx context.Context, slug string) (*OwnerNamespaceLookup, error) {
	row, err := s.q.NamespaceUserRenameBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return ownerNamespaceLookupFromRename(slug, row.Username, row.ID, row.RenamedAt, row.Deleted, true), nil
}

func (s *Service) lookupOwnerNamespaceOrgRename(ctx context.Context, slug string) (*OwnerNamespaceLookup, error) {
	row, err := s.q.NamespaceOrgRenameBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	out := ownerNamespaceLookupFromRename(slug, row.Slug, row.ID, row.RenamedAt, row.Deleted, false)
	if !row.Deleted {
		out.Org = &OwnerNamespaceLookupOrg{
			ID:          strings.TrimSpace(row.ID),
			Slug:        strings.TrimSpace(row.Slug),
			IsPersonal:  row.IsPersonal,
			OwnerUserID: strings.TrimSpace(row.OwnerUserID),
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
	out.Status = OwnerNamespaceStatusRenamedOrg
	out.Exists = true
	out.EntityKind = "org"
	return out
}
