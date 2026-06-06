package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
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
	var out TenantInvite
	err = s.pg.QueryRow(ctx, `
		INSERT INTO profiles.tenant_invites (id, tenant_id, user_id, invited_by, role, status, expires_at)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, 'pending', $6)
		RETURNING id::text, $7, user_id::text, invited_by::text, role, status, expires_at, acted_at, created_at
	`, inviteID, tenant.ID, userID, invitedBy, role, expiresAt, tenant.Slug).Scan(&out.ID, &out.Tenant, &out.UserID, &out.InvitedBy, &out.Role, &out.Status, &out.ExpiresAt, &out.ActedAt, &out.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &out, nil
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
	var rows pgx.Rows
	if status == "" {
		rows, err = s.pg.Query(ctx, `
			SELECT id::text, $2, user_id::text, invited_by::text, role, status, expires_at, acted_at, created_at
			FROM profiles.tenant_invites
			WHERE tenant_id=$1::uuid AND deleted_at IS NULL
			ORDER BY created_at DESC
		`, tenant.ID, tenant.Slug)
	} else {
		rows, err = s.pg.Query(ctx, `
			SELECT id::text, $3, user_id::text, invited_by::text, role, status, expires_at, acted_at, created_at
			FROM profiles.tenant_invites
			WHERE tenant_id=$1::uuid AND status=$2 AND deleted_at IS NULL
			ORDER BY created_at DESC
		`, tenant.ID, status, tenant.Slug)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TenantInvite, 0, 8)
	for rows.Next() {
		var item TenantInvite
		if err := rows.Scan(&item.ID, &item.Tenant, &item.UserID, &item.InvitedBy, &item.Role, &item.Status, &item.ExpiresAt, &item.ActedAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
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
	var rows pgx.Rows
	var err error
	if status == "" {
		rows, err = s.pg.Query(ctx, `
			SELECT i.id::text, o.slug, i.user_id::text, i.invited_by::text, i.role, i.status, i.expires_at, i.acted_at, i.created_at
			FROM profiles.tenant_invites i
			JOIN profiles.tenants o ON o.id=i.tenant_id
			WHERE i.user_id=$1::uuid AND i.deleted_at IS NULL AND o.deleted_at IS NULL
			ORDER BY i.created_at DESC
		`, userID)
	} else {
		rows, err = s.pg.Query(ctx, `
			SELECT i.id::text, o.slug, i.user_id::text, i.invited_by::text, i.role, i.status, i.expires_at, i.acted_at, i.created_at
			FROM profiles.tenant_invites i
			JOIN profiles.tenants o ON o.id=i.tenant_id
			WHERE i.user_id=$1::uuid AND i.status=$2 AND i.deleted_at IS NULL AND o.deleted_at IS NULL
			ORDER BY i.created_at DESC
		`, userID, status)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TenantInvite, 0, 8)
	for rows.Next() {
		var item TenantInvite
		if err := rows.Scan(&item.ID, &item.Tenant, &item.UserID, &item.InvitedBy, &item.Role, &item.Status, &item.ExpiresAt, &item.ActedAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Service) RevokeTenantInvite(ctx context.Context, tenantSlug, inviteID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return err
	}
	tag, err := s.pg.Exec(ctx, `
		UPDATE profiles.tenant_invites
		SET status='revoked', acted_at=now(), updated_at=now()
		WHERE id=$1::uuid AND tenant_id=$2::uuid AND status='pending' AND deleted_at IS NULL
	`, strings.TrimSpace(inviteID), tenant.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
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

	var tenantID, invitee, role, status string
	var expiresAt *time.Time
	if err := tx.QueryRow(ctx, `
		SELECT tenant_id::text, user_id::text, role, status, expires_at
		FROM profiles.tenant_invites
		WHERE id=$1::uuid AND deleted_at IS NULL
	`, inviteID).Scan(&tenantID, &invitee, &role, &status, &expiresAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInviteNotFound
		}
		return err
	}
	if !strings.EqualFold(invitee, userID) {
		return ErrInviteNotForUser
	}
	if status != "pending" {
		return ErrInviteNotPending
	}
	if expiresAt != nil && expiresAt.Before(time.Now().UTC()) {
		_, _ = tx.Exec(ctx, `
			UPDATE profiles.tenant_invites
			SET status='expired', acted_at=now(), updated_at=now()
			WHERE id=$1::uuid
		`, inviteID)
		return ErrInviteExpired
	}

	if target == "accepted" {
		if _, err := tx.Exec(ctx, `
			INSERT INTO profiles.tenant_memberships (tenant_id, user_id, role)
			VALUES ($1::uuid, $2::uuid, $3)
			ON CONFLICT (tenant_id, user_id) DO UPDATE SET role=EXCLUDED.role, deleted_at=NULL, updated_at=now()
		`, tenantID, userID, role); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(ctx, `
		UPDATE profiles.tenant_invites
		SET status=$2, acted_at=now(), updated_at=now()
		WHERE id=$1::uuid
	`, inviteID, target); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
