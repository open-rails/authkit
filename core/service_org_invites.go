package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type OrgInvite struct {
	ID        string     `json:"id"`
	Org       string     `json:"org"`
	UserID    string     `json:"user_id"`
	InvitedBy string     `json:"invited_by"`
	Status    string     `json:"status"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	ActedAt   *time.Time `json:"acted_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

func (s *Service) CreateOrgInvite(ctx context.Context, orgSlug, userID, invitedBy string, expiresAt *time.Time) (*OrgInvite, error) {
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
	var out OrgInvite
	err = s.pg.QueryRow(ctx, `
		INSERT INTO profiles.org_invites (org_id, user_id, invited_by, status, expires_at)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'pending', $4)
		RETURNING id::text, $5, user_id::text, invited_by::text, status, expires_at, acted_at, created_at
	`, org.ID, userID, invitedBy, expiresAt, org.Slug).Scan(&out.ID, &out.Org, &out.UserID, &out.InvitedBy, &out.Status, &out.ExpiresAt, &out.ActedAt, &out.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Service) ListOrgInvites(ctx context.Context, orgSlug, status string) ([]OrgInvite, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return nil, err
	}
	status = strings.TrimSpace(status)
	var rows pgx.Rows
	if status == "" {
		rows, err = s.pg.Query(ctx, `
			SELECT id::text, $2, user_id::text, invited_by::text, status, expires_at, acted_at, created_at
			FROM profiles.org_invites
			WHERE org_id=$1::uuid AND deleted_at IS NULL
			ORDER BY created_at DESC
		`, org.ID, org.Slug)
	} else {
		rows, err = s.pg.Query(ctx, `
			SELECT id::text, $3, user_id::text, invited_by::text, status, expires_at, acted_at, created_at
			FROM profiles.org_invites
			WHERE org_id=$1::uuid AND status=$2 AND deleted_at IS NULL
			ORDER BY created_at DESC
		`, org.ID, status, org.Slug)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]OrgInvite, 0, 8)
	for rows.Next() {
		var item OrgInvite
		if err := rows.Scan(&item.ID, &item.Org, &item.UserID, &item.InvitedBy, &item.Status, &item.ExpiresAt, &item.ActedAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Service) ListUserInvites(ctx context.Context, userID, status string) ([]OrgInvite, error) {
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
			SELECT i.id::text, o.slug, i.user_id::text, i.invited_by::text, i.status, i.expires_at, i.acted_at, i.created_at
			FROM profiles.org_invites i
			JOIN profiles.orgs o ON o.id=i.org_id
			WHERE i.user_id=$1::uuid AND i.deleted_at IS NULL AND o.deleted_at IS NULL
			ORDER BY i.created_at DESC
		`, userID)
	} else {
		rows, err = s.pg.Query(ctx, `
			SELECT i.id::text, o.slug, i.user_id::text, i.invited_by::text, i.status, i.expires_at, i.acted_at, i.created_at
			FROM profiles.org_invites i
			JOIN profiles.orgs o ON o.id=i.org_id
			WHERE i.user_id=$1::uuid AND i.status=$2 AND i.deleted_at IS NULL AND o.deleted_at IS NULL
			ORDER BY i.created_at DESC
		`, userID, status)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]OrgInvite, 0, 8)
	for rows.Next() {
		var item OrgInvite
		if err := rows.Scan(&item.ID, &item.Org, &item.UserID, &item.InvitedBy, &item.Status, &item.ExpiresAt, &item.ActedAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Service) RevokeOrgInvite(ctx context.Context, orgSlug, inviteID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return err
	}
	tag, err := s.pg.Exec(ctx, `
		UPDATE profiles.org_invites
		SET status='revoked', acted_at=now(), updated_at=now()
		WHERE id=$1::uuid AND org_id=$2::uuid AND status='pending' AND deleted_at IS NULL
	`, strings.TrimSpace(inviteID), org.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInviteNotFound
	}
	return nil
}

func (s *Service) AcceptOrgInvite(ctx context.Context, inviteID, userID string) error {
	return s.transitionOrgInvite(ctx, inviteID, userID, "accepted")
}

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

	var orgID, invitee, status string
	var expiresAt *time.Time
	if err := tx.QueryRow(ctx, `
		SELECT org_id::text, user_id::text, status, expires_at
		FROM profiles.org_invites
		WHERE id=$1::uuid AND deleted_at IS NULL
	`, inviteID).Scan(&orgID, &invitee, &status, &expiresAt); err != nil {
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
			UPDATE profiles.org_invites
			SET status='expired', acted_at=now(), updated_at=now()
			WHERE id=$1::uuid
		`, inviteID)
		return ErrInviteExpired
	}

	if target == "accepted" {
		if _, err := tx.Exec(ctx, `
			INSERT INTO profiles.org_members (org_id, user_id)
			VALUES ($1::uuid, $2::uuid)
			ON CONFLICT (org_id, user_id) DO UPDATE SET deleted_at=NULL, updated_at=now()
		`, orgID, userID); err != nil {
			return err
		}
		_, _ = tx.Exec(ctx, `
			INSERT INTO profiles.org_member_roles (org_id, user_id, role)
			SELECT $1::uuid, $2::uuid, 'member'
			WHERE EXISTS (SELECT 1 FROM profiles.org_roles WHERE org_id=$1::uuid AND role='member')
			ON CONFLICT (org_id, user_id, role) DO NOTHING
		`, orgID, userID)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE profiles.org_invites
		SET status=$2, acted_at=now(), updated_at=now()
		WHERE id=$1::uuid
	`, inviteID, target); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
