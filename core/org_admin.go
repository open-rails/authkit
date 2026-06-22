package core

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/internal/db"
)

// Org-admin (#95, Layer-2 `platform:orgs:*`): platform-admins administer ANY org
// as an ENTITY — the directory (list/inspect), soft-delete/restore, and the
// anti-takeover `recover` reset. This is ENTITY-LEVEL ONLY; a platform-admin
// never manages an org's day-to-day internals (members/roles/api-keys) — except
// the one coarse, all-or-nothing `recover` exception below.

// ErrRecoverInvalid indicates a recover request is missing the org or new owner.
var ErrRecoverInvalid = errors.New("recover requires an org and a new owner user")

// OrgAdminSummary is one row of the org directory.
type OrgAdminSummary struct {
	ID          string     `json:"id"`
	Slug        string     `json:"slug"`
	IsPersonal  bool       `json:"is_personal"`
	OwnerUserID string     `json:"owner_user_id,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
}

// OrgAdminDetail is the entity view of a single org (no internals).
type OrgAdminDetail struct {
	OrgAdminSummary
	MemberCount int64 `json:"member_count"`
}

// RecoverOrgResult reports what the anti-takeover reset changed.
type RecoverOrgResult struct {
	APIKeysRevoked     int64  `json:"api_keys_revoked"`
	RemoteAppsDisabled int64  `json:"remote_apps_disabled"`
	MembersDemoted     int64  `json:"members_demoted"`
	NewOwnerUserID     string `json:"new_owner_user_id"`
}

// AdminListOrgs lists orgs for the platform directory (paginated, optional slug
// search, optional inclusion of soft-deleted).
// Deprecated: use s.Orgs().AdminListOrgs.
func (s *Service) AdminListOrgs(ctx context.Context, search string, includeDeleted bool, limit, offset int32) ([]OrgAdminSummary, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	var sp *string
	if v := strings.TrimSpace(search); v != "" {
		sp = &v
	}
	rows, err := s.q.OrgsAdminList(ctx, db.OrgsAdminListParams{
		Search:         sp,
		IncludeDeleted: includeDeleted,
		PageLimit:      limit,
		PageOffset:     offset,
	})
	if err != nil {
		return nil, err
	}
	out := make([]OrgAdminSummary, 0, len(rows))
	for _, r := range rows {
		out = append(out, OrgAdminSummary{
			ID:          r.ID,
			Slug:        r.Slug,
			IsPersonal:  r.IsPersonal,
			OwnerUserID: strings.TrimSpace(r.OwnerUserID),
			CreatedAt:   r.CreatedAt,
			DeletedAt:   r.DeletedAt,
		})
	}
	return out, nil
}

// AdminOrgDetail returns the entity view of one org (by id), including its
// active member count. Internals (the member list itself) are NOT exposed.
// Deprecated: use s.Orgs().AdminOrgDetail.
func (s *Service) AdminOrgDetail(ctx context.Context, orgID string) (*OrgAdminDetail, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	org, err := s.ResolveOrgByID(ctx, strings.TrimSpace(orgID))
	if err != nil {
		return nil, err
	}
	count, err := s.q.OrgMemberCountByOrg(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	return &OrgAdminDetail{
		OrgAdminSummary: OrgAdminSummary{
			ID:         org.ID,
			Slug:       org.Slug,
			IsPersonal: org.IsPersonal,
		},
		MemberCount: count,
	}, nil
}

// SoftDeleteOrg soft-deletes an org (sets deleted_at). Returns whether a row
// changed. AuthKit's soft-delete does NOT cascade APP-owned resources (the app
// reacts to org-deletion for its own cleanup).
// Deprecated: use s.Orgs().SoftDeleteOrg.
func (s *Service) SoftDeleteOrg(ctx context.Context, orgID string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	n, err := s.q.OrgSoftDelete(ctx, strings.TrimSpace(orgID))
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// RestoreOrg un-deletes a soft-deleted org. Returns whether a row changed.
// Deprecated: use s.Orgs().RestoreOrg.
func (s *Service) RestoreOrg(ctx context.Context, orgID string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	n, err := s.q.OrgRestore(ctx, strings.TrimSpace(orgID))
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// TransferOrgOwnerResult reports the owner reassignment a transfer-owner made.
type TransferOrgOwnerResult struct {
	PriorOwnersDemoted int64  `json:"prior_owners_demoted"`
	NewOwnerUserID     string `json:"new_owner_user_id"`
}

// TransferOrgOwner is the SURGICAL owner reassignment (#95, platform:orgs:update)
// — the white-glove "owner-left" path that keeps the team intact (unlike the
// coarse `recover` reset, which strips every member). ATOMICALLY: demote ALL
// current `owner`-role members to `member`, then assign the prebuilt `owner`
// role (= exactly `org:*`) to the new owner. The new owner becomes a member if
// they weren't already; every other member keeps their role. Validates the new
// owner exists (→ ErrUserNotFound) and the org exists (→ ErrOrgNotFound).
// Deprecated: use s.Orgs().TransferOrgOwner.
func (s *Service) TransferOrgOwner(ctx context.Context, orgID, newOwnerUserID string) (TransferOrgOwnerResult, error) {
	var res TransferOrgOwnerResult
	if err := s.requirePG(); err != nil {
		return res, err
	}
	orgID = strings.TrimSpace(orgID)
	newOwnerUserID = strings.TrimSpace(newOwnerUserID)
	if orgID == "" || newOwnerUserID == "" {
		return res, ErrRecoverInvalid
	}
	if _, err := s.ResolveOrgByID(ctx, orgID); err != nil {
		return res, err
	}
	if _, err := s.getUserByID(ctx, newOwnerUserID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return res, ErrUserNotFound
		}
		return res, err
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.qtx(tx)

	// Ensure the prebuilt owner/member roles exist (defensive — older orgs).
	if err = qtx.OrgRolesSeedOwnerMember(ctx, db.OrgRolesSeedOwnerMemberParams{OrgID: orgID, OwnerRole: orgOwnerRole, MemberRole: orgMemberRole}); err != nil {
		return res, err
	}
	if res.PriorOwnersDemoted, err = qtx.OrgDemoteAllOwners(ctx, db.OrgDemoteAllOwnersParams{OrgID: orgID, OwnerRole: orgOwnerRole, MemberRole: orgMemberRole}); err != nil {
		return res, err
	}
	if err = qtx.OrgMembershipUpsertRole(ctx, db.OrgMembershipUpsertRoleParams{OrgID: orgID, UserID: newOwnerUserID, Role: orgOwnerRole}); err != nil {
		return res, err
	}
	if err = tx.Commit(ctx); err != nil {
		return res, err
	}
	res.NewOwnerUserID = newOwnerUserID
	return res, nil
}

// RecoverOrg is the ANTI-TAKEOVER reset for a compromised org (#95). ATOMICALLY:
// revoke ALL the org's api-keys, disable ALL its remote-applications, demote ALL
// current members (strip every role assignment), restore a clean `owner` role
// (= exactly `org:*`, in case an attacker tampered with it), and assign that
// owner to the rightful user. Bad actors are locked out; the good owner is
// restored. Coarse all-or-nothing — the single sanctioned platform reach inside
// an org.
// Deprecated: use s.Orgs().RecoverOrg.
func (s *Service) RecoverOrg(ctx context.Context, orgID, newOwnerUserID string) (RecoverOrgResult, error) {
	var res RecoverOrgResult
	if err := s.requirePG(); err != nil {
		return res, err
	}
	orgID = strings.TrimSpace(orgID)
	newOwnerUserID = strings.TrimSpace(newOwnerUserID)
	if orgID == "" || newOwnerUserID == "" {
		return res, ErrRecoverInvalid
	}
	if _, err := s.getUserByID(ctx, newOwnerUserID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return res, ErrUserNotFound
		}
		return res, err
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.qtx(tx)

	if res.APIKeysRevoked, err = qtx.APIKeyRevokeAllByOrg(ctx, orgID); err != nil {
		return res, err
	}
	if res.RemoteAppsDisabled, err = qtx.RemoteApplicationDisableAllByOrg(ctx, orgID); err != nil {
		return res, err
	}
	if res.MembersDemoted, err = qtx.OrgMembershipsSoftDeleteAllByOrg(ctx, orgID); err != nil {
		return res, err
	}
	// Restore a clean owner/member role pair, then reset owner to its apex grants
	// (org:* plus each app resource namespace, see ownerGrantTokens).
	if err = qtx.OrgRolesSeedOwnerMember(ctx, db.OrgRolesSeedOwnerMemberParams{OrgID: orgID, OwnerRole: orgOwnerRole, MemberRole: orgMemberRole}); err != nil {
		return res, err
	}
	if err = qtx.OrgRolePermissionsDelete(ctx, db.OrgRolePermissionsDeleteParams{OrgID: orgID, Role: orgOwnerRole}); err != nil {
		return res, err
	}
	if err = s.seedOwnerGrants(ctx, qtx, orgID); err != nil {
		return res, err
	}
	if err = qtx.OrgMembershipUpsertRole(ctx, db.OrgMembershipUpsertRoleParams{OrgID: orgID, UserID: newOwnerUserID, Role: orgOwnerRole}); err != nil {
		return res, err
	}
	if err = tx.Commit(ctx); err != nil {
		return res, err
	}
	res.NewOwnerUserID = newOwnerUserID
	return res, nil
}
