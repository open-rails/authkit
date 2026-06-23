package authcore

// Group-invite flow (#111): the human "invite a user to a permission-group with a
// role" lifecycle. An invite names a single role
// that must be valid for the group's TYPE catalog (or a custom role for
// custom-enabled types) — validated exactly like AssignGroupRole. Accepting an
// invite assigns that role to the invited user (atomically with the status flip).
// Group ids stay INTERNAL; callers address the owning group by (persona, resource_slug).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/db"
)

// Group-invite statuses (mirror the group_invites_status_chk constraint).
const (
	GroupInviteStatusPending  = "pending"
	GroupInviteStatusAccepted = "accepted"
	GroupInviteStatusDeclined = "declined"
	GroupInviteStatusRevoked  = "revoked"
	GroupInviteStatusExpired  = "expired"
)

var (
	// ErrInviteNotFound indicates no live invite matched the lookup.
	ErrInviteNotFound = errors.New("group_invite_not_found")
	// ErrInviteNotPending indicates an action requiring a pending invite hit one
	// already accepted/declined/revoked/expired.
	ErrInviteNotPending = errors.New("group_invite_not_pending")
)

// GroupInvite is the non-secret view of a pending/acted invite. Role resolves via
// the type catalog / custom roles (not a DB FK); on accept it is assigned to UserID.
type GroupInvite struct {
	ID        string
	GroupID   string
	UserID    string
	InvitedBy string
	Role      string
	Status    string
	ExpiresAt *time.Time
	ActedAt   *time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CreateGroupInvite records a pending invite for userID to hold role in the group
// addressed by (groupType, resourceRef), attributed to invitedBy. The role is
// validated against the type catalog (catalog role, or any role for custom-enabled
// types) exactly as AssignGroupRole does. Returns the new invite's id. A pending
// invite for the same (group, user) is unique at the DB; a duplicate is rejected.
func (s *Service) CreateGroupInvite(ctx context.Context, groupType, resourceRef, userID, role, invitedBy string) (string, error) {
	if err := s.requirePG(); err != nil {
		return "", err
	}
	role = strings.ToLower(strings.TrimSpace(role))
	userID = strings.TrimSpace(userID)
	invitedBy = strings.TrimSpace(invitedBy)
	if userID == "" || invitedBy == "" {
		return "", errors.New("invalid_invite")
	}
	if !s.validRoleForPersona(s.groupSchemaOrDefault(), groupType, role) {
		return "", fmt.Errorf("role %q is not assignable in a %q group", role, groupType)
	}
	gid, err := s.resolveGroupID(ctx, s.groupStore(), strings.TrimSpace(groupType), strings.TrimSpace(resourceRef))
	if err != nil {
		return "", err
	}
	q := db.ForSchema(s.pg, s.dbSchema())
	var id string
	err = q.QueryRow(ctx,
		`INSERT INTO profiles.group_invites (group_id, user_id, invited_by, role)
		 VALUES ($1::uuid, $2::uuid, $3::uuid, $4)
		 RETURNING id::text`,
		gid, userID, invitedBy, role).Scan(&id)
	if err != nil {
		return "", err
	}
	return id, nil
}

// ListGroupInvites returns every (non-deleted) invite of the group addressed by
// (groupType, resourceRef), including acted ones, newest first.
func (s *Service) ListGroupInvites(ctx context.Context, groupType, resourceRef string) ([]GroupInvite, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	gid, err := s.resolveGroupID(ctx, s.groupStore(), strings.TrimSpace(groupType), strings.TrimSpace(resourceRef))
	if err != nil {
		return nil, err
	}
	q := db.ForSchema(s.pg, s.dbSchema())
	rows, err := q.Query(ctx,
		`SELECT id::text, group_id::text, user_id::text, invited_by::text, role, status,
		        expires_at, acted_at, created_at, updated_at
		 FROM profiles.group_invites
		 WHERE group_id = $1::uuid AND deleted_at IS NULL
		 ORDER BY created_at DESC`, gid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]GroupInvite, 0)
	for rows.Next() {
		var inv GroupInvite
		if err := rows.Scan(&inv.ID, &inv.GroupID, &inv.UserID, &inv.InvitedBy, &inv.Role, &inv.Status,
			&inv.ExpiresAt, &inv.ActedAt, &inv.CreatedAt, &inv.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

// AcceptGroupInvite flips a pending invite (addressed by id) to accepted and, in
// the same transaction, assigns the invited role to userID. userID must be the
// invited user. ErrInviteNotFound if no live pending invite for (id, userID)
// exists. Idempotency: a second accept finds no pending row and returns
// ErrInviteNotPending.
func (s *Service) AcceptGroupInvite(ctx context.Context, inviteID, userID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	inviteID = strings.TrimSpace(inviteID)
	userID = strings.TrimSpace(userID)
	if inviteID == "" || userID == "" {
		return errors.New("invalid_invite")
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := db.ForSchema(tx, s.dbSchema())

	// Lock the invite row; ensure it's this user's and still pending. Carry the
	// group_id/persona + role out so the assignment uses the invite's own attribution.
	var groupID, persona, role, status string
	var expiresAt *time.Time
	err = q.QueryRow(ctx,
		`SELECT i.group_id::text, g.persona, i.role, i.status, i.expires_at
		 FROM profiles.group_invites i
		 JOIN profiles.permission_groups g ON g.id = i.group_id
		 WHERE i.id = $1::uuid AND i.user_id = $2::uuid AND i.deleted_at IS NULL
		 FOR UPDATE`,
		inviteID, userID).Scan(&groupID, &persona, &role, &status, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInviteNotFound
	}
	if err != nil {
		return err
	}
	if status != GroupInviteStatusPending {
		return ErrInviteNotPending
	}
	if expiresAt != nil && !expiresAt.After(time.Now().UTC()) {
		// Expired: reflect it and refuse, rather than silently accepting.
		if _, uerr := q.Exec(ctx,
			`UPDATE profiles.group_invites SET status = $2, acted_at = now(), updated_at = now()
			 WHERE id = $1::uuid`, inviteID, GroupInviteStatusExpired); uerr != nil {
			return uerr
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			return cerr
		}
		return ErrInviteNotPending
	}

	st := NewPermissionGroupStore(q)
	if err := s.requireMFAForRoleAssignment(ctx, q, persona, userID, SubjectKindUser, role); err != nil {
		return err
	}
	if err := st.AssignRole(ctx, groupID, userID, SubjectKindUser, role); err != nil {
		return err
	}
	if _, err := q.Exec(ctx,
		`UPDATE profiles.group_invites SET status = $2, acted_at = now(), updated_at = now()
		 WHERE id = $1::uuid`, inviteID, GroupInviteStatusAccepted); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// DeclineGroupInvite flips a pending invite (addressed by id) to declined. userID
// must be the invited user. No role is assigned. ErrInviteNotFound if no live
// pending invite for (id, userID) exists; ErrInviteNotPending if already acted.
func (s *Service) DeclineGroupInvite(ctx context.Context, inviteID, userID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	inviteID = strings.TrimSpace(inviteID)
	userID = strings.TrimSpace(userID)
	if inviteID == "" || userID == "" {
		return errors.New("invalid_invite")
	}
	q := db.ForSchema(s.pg, s.dbSchema())
	tag, err := q.Exec(ctx,
		`UPDATE profiles.group_invites SET status = $3, acted_at = now(), updated_at = now()
		 WHERE id = $1::uuid AND user_id = $2::uuid AND status = $4 AND deleted_at IS NULL`,
		inviteID, userID, GroupInviteStatusDeclined, GroupInviteStatusPending)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return s.inviteMissOrNotPending(ctx, inviteID, userID)
	}
	return nil
}

// RevokeGroupInvite flips a pending invite to revoked. It is scoped to the group
// addressed by (groupType, resourceRef) so a manager cannot revoke an invite from
// another group. ErrInviteNotFound if absent; ErrInviteNotPending if already acted.
func (s *Service) RevokeGroupInvite(ctx context.Context, groupType, resourceRef, inviteID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	inviteID = strings.TrimSpace(inviteID)
	if inviteID == "" {
		return errors.New("invalid_invite")
	}
	gid, err := s.resolveGroupID(ctx, s.groupStore(), strings.TrimSpace(groupType), strings.TrimSpace(resourceRef))
	if err != nil {
		return err
	}
	q := db.ForSchema(s.pg, s.dbSchema())
	tag, err := q.Exec(ctx,
		`UPDATE profiles.group_invites SET status = $3, acted_at = now(), updated_at = now()
		 WHERE id = $1::uuid AND group_id = $2::uuid AND status = $4 AND deleted_at IS NULL`,
		inviteID, gid, GroupInviteStatusRevoked, GroupInviteStatusPending)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return s.inviteMissOrNotPendingInGroup(ctx, inviteID, gid)
	}
	return nil
}

// inviteMissOrNotPending disambiguates a no-op (id,user) status update: absent
// row => ErrInviteNotFound, else => ErrInviteNotPending (already acted).
func (s *Service) inviteMissOrNotPending(ctx context.Context, inviteID, userID string) error {
	q := db.ForSchema(s.pg, s.dbSchema())
	var exists bool
	err := q.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM profiles.group_invites
		   WHERE id = $1::uuid AND user_id = $2::uuid AND deleted_at IS NULL)`,
		inviteID, userID).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return ErrInviteNotFound
	}
	return ErrInviteNotPending
}

// inviteMissOrNotPendingInGroup is the group-scoped variant for revoke.
func (s *Service) inviteMissOrNotPendingInGroup(ctx context.Context, inviteID, groupID string) error {
	q := db.ForSchema(s.pg, s.dbSchema())
	var exists bool
	err := q.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM profiles.group_invites
		   WHERE id = $1::uuid AND group_id = $2::uuid AND deleted_at IS NULL)`,
		inviteID, groupID).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return ErrInviteNotFound
	}
	return ErrInviteNotPending
}
