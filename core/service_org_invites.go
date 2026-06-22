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

type OrgInvite struct {
	ID        string     `json:"id"`
	Org       string     `json:"org"`
	UserID    string     `json:"user_id"`
	InvitedBy string     `json:"invited_by"`
	Role      string     `json:"role"`
	Status    string     `json:"status"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	ActedAt   *time.Time `json:"acted_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// ValidateInviteRoleGrant enforces the no-escalation invariant for a org
// invite: the GRANTOR (the inviter) must currently hold every permission the
// invited role confers. A global admin or an actor holding `*` passes. Returns
// ErrInviteRoleExceedsGrantor when the grantor's authority is insufficient.
//
// Called at invite-create time AND re-checked at accept time, since the
// inviter's permissions may have been reduced between creating the invite and
// the invitee accepting it (a stale pending "owner" invite must not still grant
// owner once its creator has been demoted).
// Deprecated: use s.Orgs().ValidateInviteRoleGrant.
func (s *Service) ValidateInviteRoleGrant(ctx context.Context, orgSlug, grantorUserID, role string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	grantorUserID = strings.TrimSpace(grantorUserID)
	if grantorUserID == "" {
		return ErrInviteRoleExceedsGrantor
	}
	role = strings.TrimSpace(role)
	if role == "" {
		role = "member"
	}
	rolePerms, err := s.EffectiveRolePermissions(ctx, orgSlug, role)
	if err != nil {
		return err
	}
	// Platform admins may grant any role; otherwise the grantor's own effective
	// permissions must cover the role (ValidateGrant computes the superset). The
	// legacy global-admin bypass is now a Layer-2 platform check: a platform
	// super-admin holds platform:orgs:update (via platform:*), so they bypass the
	// org-grantor superset check just like the old global admin did.
	grantorAll, _ := s.HasPlatformPermission(ctx, grantorUserID, PermPlatformOrgsUpdate)
	if _, offending, verr := s.ValidateGrant(ctx, orgSlug, grantorUserID, rolePerms, grantorAll); verr != nil {
		return verr
	} else if len(offending) > 0 {
		return ErrInviteRoleExceedsGrantor
	}
	return nil
}

// Deprecated: use s.Orgs().CreateOrgInvite.
func (s *Service) CreateOrgInvite(ctx context.Context, orgSlug, userID, invitedBy, role string, expiresAt *time.Time) (*OrgInvite, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return nil, err
	}
	userID = strings.TrimSpace(userID)
	invitedBy = strings.TrimSpace(invitedBy)
	if userID == "" || invitedBy == "" {
		return nil, fmt.Errorf("invalid_user")
	}
	role = strings.TrimSpace(role)
	if role == "" {
		role = "member"
	}
	inviteID, err := newUUIDV7String()
	if err != nil {
		return nil, err
	}
	row, err := s.q.OrgInviteInsert(ctx, db.OrgInviteInsertParams{
		ID:        inviteID,
		OrgID:     org.ID,
		UserID:    userID,
		InvitedBy: invitedBy,
		Role:      role,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return nil, err
	}
	return &OrgInvite{
		ID:        row.ID,
		Org:       org.Slug,
		UserID:    row.UserID,
		InvitedBy: row.InvitedBy,
		Role:      row.Role,
		Status:    row.Status,
		ExpiresAt: row.ExpiresAt,
		ActedAt:   row.ActedAt,
		CreatedAt: row.CreatedAt,
	}, nil
}

// Deprecated: use s.Orgs().ListOrgInvites.
func (s *Service) ListOrgInvites(ctx context.Context, orgSlug, status string) ([]OrgInvite, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return nil, err
	}
	status = strings.TrimSpace(status)
	out := make([]OrgInvite, 0, 8)
	if status == "" {
		rows, err := s.q.OrgInvitesByOrg(ctx, org.ID)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			out = append(out, OrgInvite{ID: r.ID, Org: org.Slug, UserID: r.UserID, InvitedBy: r.InvitedBy, Role: r.Role, Status: r.Status, ExpiresAt: r.ExpiresAt, ActedAt: r.ActedAt, CreatedAt: r.CreatedAt})
		}
		return out, nil
	}
	rows, err := s.q.OrgInvitesByOrgStatus(ctx, db.OrgInvitesByOrgStatusParams{OrgID: org.ID, Status: status})
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out = append(out, OrgInvite{ID: r.ID, Org: org.Slug, UserID: r.UserID, InvitedBy: r.InvitedBy, Role: r.Role, Status: r.Status, ExpiresAt: r.ExpiresAt, ActedAt: r.ActedAt, CreatedAt: r.CreatedAt})
	}
	return out, nil
}

// Deprecated: use s.Orgs().ListUserInvites.
func (s *Service) ListUserInvites(ctx context.Context, userID, status string) ([]OrgInvite, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, fmt.Errorf("invalid_user")
	}
	status = strings.TrimSpace(status)
	out := make([]OrgInvite, 0, 8)
	if status == "" {
		rows, err := s.q.OrgInvitesByUser(ctx, userID)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			out = append(out, OrgInvite{ID: r.ID, Org: r.Slug, UserID: r.UserID, InvitedBy: r.InvitedBy, Role: r.Role, Status: r.Status, ExpiresAt: r.ExpiresAt, ActedAt: r.ActedAt, CreatedAt: r.CreatedAt})
		}
		return out, nil
	}
	rows, err := s.q.OrgInvitesByUserStatus(ctx, db.OrgInvitesByUserStatusParams{UserID: userID, Status: status})
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out = append(out, OrgInvite{ID: r.ID, Org: r.Slug, UserID: r.UserID, InvitedBy: r.InvitedBy, Role: r.Role, Status: r.Status, ExpiresAt: r.ExpiresAt, ActedAt: r.ActedAt, CreatedAt: r.CreatedAt})
	}
	return out, nil
}

// Deprecated: use s.Orgs().RevokeOrgInvite.
func (s *Service) RevokeOrgInvite(ctx context.Context, orgSlug, inviteID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return err
	}
	n, err := s.q.OrgInviteRevoke(ctx, db.OrgInviteRevokeParams{ID: strings.TrimSpace(inviteID), OrgID: org.ID})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrInviteNotFound
	}
	return nil
}

// Deprecated: use s.Orgs().AcceptOrgInvite.
func (s *Service) AcceptOrgInvite(ctx context.Context, inviteID, userID string) error {
	return s.transitionOrgInvite(ctx, inviteID, userID, "accepted")
}

// Deprecated: use s.Orgs().DeclineOrgInvite.
func (s *Service) DeclineOrgInvite(ctx context.Context, inviteID, userID string) error {
	return s.transitionOrgInvite(ctx, inviteID, userID, "declined")
}

func (s *Service) transitionOrgInvite(ctx context.Context, inviteID, userID, target string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	inviteID = strings.TrimSpace(inviteID)
	userID = strings.TrimSpace(userID)
	if inviteID == "" || userID == "" {
		return fmt.Errorf("invalid_request")
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.qtx(tx)

	inv, err := qtx.OrgInviteForUpdate(ctx, inviteID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInviteNotFound
		}
		return err
	}
	if !strings.EqualFold(inv.UserID, userID) {
		return ErrInviteNotForUser
	}
	if inv.Status != "pending" {
		return ErrInviteNotPending
	}
	if inv.ExpiresAt != nil && inv.ExpiresAt.Before(time.Now().UTC()) {
		_ = qtx.OrgInviteMarkExpired(ctx, inviteID)
		return ErrInviteExpired
	}

	if target == "accepted" {
		// NO-ESCALATION (re-check at accept time): re-validate that the inviter
		// STILL has authority to grant inv.Role. Their permissions may have been
		// reduced since the invite was created, so a pending high-privilege invite
		// must not be honored once its creator can no longer grant that role.
		var invitedBy string
		if err := tx.QueryRow(ctx,
			`SELECT invited_by::text FROM profiles.org_invites WHERE id = $1::uuid`, inviteID,
		).Scan(&invitedBy); err != nil {
			return err
		}
		slugRow, err := qtx.OrgSlugAndPersonalByID(ctx, inv.OrgID)
		if err != nil {
			return err
		}
		if err := s.ValidateInviteRoleGrant(ctx, slugRow.Slug, invitedBy, inv.Role); err != nil {
			return err
		}
		if err := qtx.OrgMembershipUpsertRole(ctx, db.OrgMembershipUpsertRoleParams{OrgID: inv.OrgID, UserID: userID, Role: inv.Role}); err != nil {
			return err
		}
	}

	if err := qtx.OrgInviteSetStatus(ctx, db.OrgInviteSetStatusParams{ID: inviteID, Status: target}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
