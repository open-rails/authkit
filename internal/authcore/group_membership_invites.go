package authcore

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

// Known-user permission-group invites (#147). The invitee ALREADY has an account,
// so there is NO token: the pending row is keyed to the target UserID and the
// recipient accepts/declines with their OWN auth (authenticated AS that user is the
// credential). This is the consent-based counterpart to the silent owner direct-add
// and to the stranger account_registration_invites code.

const defaultGroupMembershipInviteTTL = 7 * 24 * time.Hour

// ErrGroupMembershipInviteNotFound indicates no pending invite matched (wrong id,
// not the caller's, or already accepted/declined/revoked/expired).
var ErrGroupMembershipInviteNotFound = errors.New("group_membership_invite_not_found")

// GroupMembershipInvite is a pending known-user group invite.
type GroupMembershipInvite struct {
	ID           string
	Persona      string
	InstanceSlug string
	Role         string
	InvitedBy    string
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

// CreateGroupMembershipInvite records a pending invite for an EXISTING user. The
// actor must hold the same no-escalation authority required to assign the role
// directly; the role is granted only when the invitee accepts. Idempotent on a
// pending (group, user, role) — a duplicate invite returns the existing one.
func (s *Service) CreateGroupMembershipInvite(ctx context.Context, actorUserID, persona, instanceSlug, targetUserID, role string) (GroupMembershipInvite, error) {
	if err := s.requirePG(); err != nil {
		return GroupMembershipInvite{}, err
	}
	actorUserID = strings.TrimSpace(actorUserID)
	targetUserID = strings.TrimSpace(targetUserID)
	role = strings.TrimSpace(role)
	if actorUserID == "" || targetUserID == "" || role == "" {
		return GroupMembershipInvite{}, authkit.ErrInvalidInvite
	}
	sch := s.groupSchemaOrDefault()
	if !s.validRoleForPersona(sch, persona, role) {
		return GroupMembershipInvite{}, authkit.ErrInvalidRole
	}
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, persona, instanceSlug)
	if err != nil {
		return GroupMembershipInvite{}, err
	}
	// Same authority gate as a direct assignment (capability + no-escalation).
	if err := s.authorizeRoleChange(ctx, st, sch, persona, gid, actorUserID, role); err != nil {
		return GroupMembershipInvite{}, err
	}
	expiresAt := time.Now().UTC().Add(defaultGroupMembershipInviteTTL)
	q := db.ForSchema(s.pg, s.dbSchema())
	var id string
	var createdAt time.Time
	err = q.QueryRow(ctx,
		`INSERT INTO profiles.group_membership_invites
		   (permission_group_id, user_id, role, invited_by, expires_at)
		 VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5)
		 ON CONFLICT (permission_group_id, user_id, role)
		   WHERE accepted_at IS NULL AND declined_at IS NULL AND revoked_at IS NULL
		   DO UPDATE SET invited_by = EXCLUDED.invited_by, expires_at = EXCLUDED.expires_at,
		                 updated_at = now()
		 RETURNING id::text, created_at`,
		gid, targetUserID, role, actorUserID, expiresAt).Scan(&id, &createdAt)
	if err != nil {
		return GroupMembershipInvite{}, err
	}
	return GroupMembershipInvite{
		ID: id, Persona: persona, InstanceSlug: strings.TrimSpace(instanceSlug),
		Role: role, InvitedBy: actorUserID, ExpiresAt: expiresAt, CreatedAt: createdAt,
	}, nil
}

// ListPendingGroupMembershipInvites returns the caller's open invites.
func (s *Service) ListPendingGroupMembershipInvites(ctx context.Context, userID string) ([]GroupMembershipInvite, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, errors.New("invalid_user")
	}
	q := db.ForSchema(s.pg, s.dbSchema())
	rows, err := q.Query(ctx,
		`SELECT i.id::text, g.persona, COALESCE(g.instance_slug, ''), i.role,
		        i.invited_by::text, i.expires_at, i.created_at
		   FROM profiles.group_membership_invites i
		   JOIN profiles.permission_groups g ON g.id = i.permission_group_id
		  WHERE i.user_id = $1::uuid
		    AND i.accepted_at IS NULL AND i.declined_at IS NULL AND i.revoked_at IS NULL
		    AND i.expires_at > now()
		  ORDER BY i.created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]GroupMembershipInvite, 0)
	for rows.Next() {
		var inv GroupMembershipInvite
		if err := rows.Scan(&inv.ID, &inv.Persona, &inv.InstanceSlug, &inv.Role,
			&inv.InvitedBy, &inv.ExpiresAt, &inv.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

// AcceptGroupMembershipInvite grants the invited role to the caller (own-auth
// acceptance) and marks the invite accepted. Single-use.
func (s *Service) AcceptGroupMembershipInvite(ctx context.Context, userID, inviteID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	userID = strings.TrimSpace(userID)
	inviteID = strings.TrimSpace(inviteID)
	if userID == "" || inviteID == "" {
		return ErrGroupMembershipInviteNotFound
	}
	q := db.ForSchema(s.pg, s.dbSchema())
	// Atomically claim the pending invite (single-use) and read its group + role.
	var gid, role, persona string
	err := q.QueryRow(ctx,
		`UPDATE profiles.group_membership_invites i
		    SET accepted_at = now(), updated_at = now()
		  FROM profiles.permission_groups g
		  WHERE i.id = $1::uuid AND i.user_id = $2::uuid AND g.id = i.permission_group_id
		    AND i.accepted_at IS NULL AND i.declined_at IS NULL AND i.revoked_at IS NULL
		    AND i.expires_at > now()
		  RETURNING i.permission_group_id::text, i.role, g.persona`,
		inviteID, userID).Scan(&gid, &role, &persona)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrGroupMembershipInviteNotFound
	}
	if err != nil {
		return err
	}
	// A role requiring MFA can only be held by an enrolled user (checked at accept,
	// not invite time, since enrollment can change in between).
	if err := s.requireMFAForRoleAssignment(ctx, q, gid, persona, userID, SubjectKindUser, role); err != nil {
		return err
	}
	return s.groupStore().AssignRole(ctx, gid, userID, SubjectKindUser, role)
}

// DeclineGroupMembershipInvite marks the caller's pending invite declined.
func (s *Service) DeclineGroupMembershipInvite(ctx context.Context, userID, inviteID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	userID = strings.TrimSpace(userID)
	inviteID = strings.TrimSpace(inviteID)
	if userID == "" || inviteID == "" {
		return ErrGroupMembershipInviteNotFound
	}
	q := db.ForSchema(s.pg, s.dbSchema())
	tag, err := q.Exec(ctx,
		`UPDATE profiles.group_membership_invites
		    SET declined_at = now(), updated_at = now()
		  WHERE id = $1::uuid AND user_id = $2::uuid
		    AND accepted_at IS NULL AND declined_at IS NULL AND revoked_at IS NULL`,
		inviteID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrGroupMembershipInviteNotFound
	}
	return nil
}
