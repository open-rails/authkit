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
	qtx := s.q.WithTx(tx)

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
		if err := qtx.TenantMembershipUpsertRole(ctx, db.TenantMembershipUpsertRoleParams{TenantID: inv.TenantID, UserID: userID, Role: inv.Role}); err != nil {
			return err
		}
	}

	if err := qtx.TenantInviteSetStatus(ctx, db.TenantInviteSetStatusParams{ID: inviteID, Status: target}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
