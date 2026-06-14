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

type TenantInvite struct {
	ID        string     `json:"id"`
	Tenant    string     `json:"tenant"`
	UserID    string     `json:"user_id"`
	InvitedBy string     `json:"invited_by"`
	Role      string     `json:"role"`
	Status    string     `json:"status"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	ActedAt   *time.Time `json:"acted_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// ValidateInviteRoleGrant enforces the no-escalation invariant for a tenant
// invite: the GRANTOR (the inviter) must currently hold every permission the
// invited role confers. A global admin or an actor holding `*` passes. Returns
// ErrInviteRoleExceedsGrantor when the grantor's authority is insufficient.
//
// Called at invite-create time AND re-checked at accept time, since the
// inviter's permissions may have been reduced between creating the invite and
// the invitee accepting it (a stale pending "owner" invite must not still grant
// owner once its creator has been demoted).
func (s *Service) ValidateInviteRoleGrant(ctx context.Context, tenantSlug, grantorUserID, role string) error {
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
	rolePerms, err := s.EffectiveRolePermissions(ctx, tenantSlug, role)
	if err != nil {
		return err
	}
	// Global admins may grant any role; otherwise the grantor's own effective
	// permissions must cover the role (ValidateGrant computes the superset).
	grantorAll, _ := s.q.GlobalUserHasActiveRole(ctx, db.GlobalUserHasActiveRoleParams{UserID: grantorUserID, Slug: "admin"})
	if _, offending, verr := s.ValidateGrant(ctx, tenantSlug, grantorUserID, rolePerms, grantorAll); verr != nil {
		return verr
	} else if len(offending) > 0 {
		return ErrInviteRoleExceedsGrantor
	}
	return nil
}

func (s *Service) CreateTenantInvite(ctx context.Context, tenantSlug, userID, invitedBy, role string, expiresAt *time.Time) (*TenantInvite, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
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
	row, err := s.q.TenantInviteInsert(ctx, db.TenantInviteInsertParams{
		ID:        inviteID,
		TenantID:  tenant.ID,
		UserID:    userID,
		InvitedBy: invitedBy,
		Role:      role,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return nil, err
	}
	return &TenantInvite{
		ID:        row.ID,
		Tenant:    tenant.Slug,
		UserID:    row.UserID,
		InvitedBy: row.InvitedBy,
		Role:      row.Role,
		Status:    row.Status,
		ExpiresAt: row.ExpiresAt,
		ActedAt:   row.ActedAt,
		CreatedAt: row.CreatedAt,
	}, nil
}

func (s *Service) ListTenantInvites(ctx context.Context, tenantSlug, status string) ([]TenantInvite, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return nil, err
	}
	status = strings.TrimSpace(status)
	out := make([]TenantInvite, 0, 8)
	if status == "" {
		rows, err := s.q.TenantInvitesByTenant(ctx, tenant.ID)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			out = append(out, TenantInvite{ID: r.ID, Tenant: tenant.Slug, UserID: r.UserID, InvitedBy: r.InvitedBy, Role: r.Role, Status: r.Status, ExpiresAt: r.ExpiresAt, ActedAt: r.ActedAt, CreatedAt: r.CreatedAt})
		}
		return out, nil
	}
	rows, err := s.q.TenantInvitesByTenantStatus(ctx, db.TenantInvitesByTenantStatusParams{TenantID: tenant.ID, Status: status})
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out = append(out, TenantInvite{ID: r.ID, Tenant: tenant.Slug, UserID: r.UserID, InvitedBy: r.InvitedBy, Role: r.Role, Status: r.Status, ExpiresAt: r.ExpiresAt, ActedAt: r.ActedAt, CreatedAt: r.CreatedAt})
	}
	return out, nil
}

func (s *Service) ListUserInvites(ctx context.Context, userID, status string) ([]TenantInvite, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, fmt.Errorf("invalid_user")
	}
	status = strings.TrimSpace(status)
	out := make([]TenantInvite, 0, 8)
	if status == "" {
		rows, err := s.q.TenantInvitesByUser(ctx, userID)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			out = append(out, TenantInvite{ID: r.ID, Tenant: r.Slug, UserID: r.UserID, InvitedBy: r.InvitedBy, Role: r.Role, Status: r.Status, ExpiresAt: r.ExpiresAt, ActedAt: r.ActedAt, CreatedAt: r.CreatedAt})
		}
		return out, nil
	}
	rows, err := s.q.TenantInvitesByUserStatus(ctx, db.TenantInvitesByUserStatusParams{UserID: userID, Status: status})
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out = append(out, TenantInvite{ID: r.ID, Tenant: r.Slug, UserID: r.UserID, InvitedBy: r.InvitedBy, Role: r.Role, Status: r.Status, ExpiresAt: r.ExpiresAt, ActedAt: r.ActedAt, CreatedAt: r.CreatedAt})
	}
	return out, nil
}

func (s *Service) RevokeTenantInvite(ctx context.Context, tenantSlug, inviteID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return err
	}
	n, err := s.q.TenantInviteRevoke(ctx, db.TenantInviteRevokeParams{ID: strings.TrimSpace(inviteID), TenantID: tenant.ID})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrInviteNotFound
	}
	return nil
}

func (s *Service) AcceptTenantInvite(ctx context.Context, inviteID, userID string) error {
	return s.transitionTenantInvite(ctx, inviteID, userID, "accepted")
}

func (s *Service) DeclineTenantInvite(ctx context.Context, inviteID, userID string) error {
	return s.transitionTenantInvite(ctx, inviteID, userID, "declined")
}

func (s *Service) transitionTenantInvite(ctx context.Context, inviteID, userID, target string) error {
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

	inv, err := qtx.TenantInviteForUpdate(ctx, inviteID)
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
		_ = qtx.TenantInviteMarkExpired(ctx, inviteID)
		return ErrInviteExpired
	}

	if target == "accepted" {
		// NO-ESCALATION (re-check at accept time): re-validate that the inviter
		// STILL has authority to grant inv.Role. Their permissions may have been
		// reduced since the invite was created, so a pending high-privilege invite
		// must not be honored once its creator can no longer grant that role.
		var invitedBy string
		if err := tx.QueryRow(ctx,
			`SELECT invited_by::text FROM profiles.tenant_invites WHERE id = $1::uuid`, inviteID,
		).Scan(&invitedBy); err != nil {
			return err
		}
		slugRow, err := qtx.TenantSlugAndPersonalByID(ctx, inv.TenantID)
		if err != nil {
			return err
		}
		if err := s.ValidateInviteRoleGrant(ctx, slugRow.Slug, invitedBy, inv.Role); err != nil {
			return err
		}
		if err := qtx.TenantMembershipUpsertRole(ctx, db.TenantMembershipUpsertRoleParams{TenantID: inv.TenantID, UserID: userID, Role: inv.Role}); err != nil {
			return err
		}
	}

	if err := qtx.TenantInviteSetStatus(ctx, db.TenantInviteSetStatusParams{ID: inviteID, Status: target}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
