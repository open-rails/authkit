package embedded

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

// lockAuthority precedes every group, account, MFA and session row lock in an
// authority mutation. A schema-wide boundary also protects ancestor grants and
// mutable role definitions. Login, verification and session reads do not use it.
func (s *engine) lockAuthority(ctx context.Context, q db.DBTX) error {
	_, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "authkit.authority."+s.dbSchema())
	return err
}

// Authority reads after a queued lock must use a new statement snapshot even
// when a host configures its pool with a stronger default isolation level.
func (s *engine) beginAuthorityTransaction(ctx context.Context) (pgx.Tx, error) {
	return s.pg.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
}

func (s *engine) withAuthorityMutation(ctx context.Context, apply func(*PermissionGroupStore) error) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	tx, err := s.beginAuthorityTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	st := s.groupStoreFor(tx)
	if err := s.lockAuthority(ctx, st.q); err != nil {
		return err
	}
	if err := apply(st); err != nil {
		return err
	}
	if err := s.revokeUncoveredCredentials(ctx, st, st.touched...); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// revokeUncoveredCredentials revokes live invite links, account invitations and
// API keys whose creator could no longer issue their role, after grants in the
// touched groups (and so their subtrees) changed. A credential never outlives
// the authority that issued it; otherwise a demoted creator could redeem their
// own link, or keep using their own key, to regain the role.
func (s *engine) revokeUncoveredCredentials(ctx context.Context, st *PermissionGroupStore, touched ...authorityTouch) error {
	type credential struct {
		table, id, groupID, creator string
		persona                     authkit.Persona
		role                        authkit.Role
	}
	seen := map[authorityTouch]bool{}
	var creds []credential
	for _, t := range touched {
		if seen[t] {
			continue
		}
		seen[t] = true
		rows, err := st.q.Query(ctx, `WITH RECURSIVE subtree AS (
  SELECT id, persona FROM permission_groups WHERE id=$1::uuid
  UNION ALL SELECT g.id, g.persona FROM permission_groups g JOIN subtree p ON g.parent_id=p.id WHERE g.deleted_at IS NULL)
SELECT 'group_invite_links', l.id::text, l.permission_group_id::text, t.persona, l.role, l.invited_by::text
  FROM group_invite_links l JOIN subtree t ON t.id=l.permission_group_id
 WHERE l.revoked_at IS NULL AND l.redeemed_at IS NULL AND (l.expires_at IS NULL OR l.expires_at>now())
   AND ($2='' OR l.invited_by::text=$2)
UNION ALL
SELECT 'account_registration_invites', a.id::text, a.permission_group_id::text, t.persona, a.role, a.invited_by::text
  FROM account_registration_invites a JOIN subtree t ON t.id=a.permission_group_id
 WHERE a.revoked_at IS NULL AND a.consumed_at IS NULL AND a.expires_at>now()
   AND ($2='' OR a.invited_by::text=$2)
UNION ALL
SELECT 'api_keys', k.id::text, k.permission_group_id::text, t.persona, k.role, k.created_by::text
  FROM api_keys k JOIN subtree t ON t.id=k.permission_group_id
 WHERE k.revoked_at IS NULL AND k.created_by IS NOT NULL AND (k.expires_at IS NULL OR k.expires_at>now())
   AND ($2='' OR k.created_by::text=$2)`, t.groupID, t.userID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var c credential
			if err := rows.Scan(&c.table, &c.id, &c.groupID, &c.persona, &c.role, &c.creator); err != nil {
				rows.Close()
				return err
			}
			creds = append(creds, c)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
	}
	sch := s.groupSchemaOrDefault()
	revoked := map[string]bool{}
	for _, c := range creds {
		if revoked[c.id] {
			continue
		}
		capability := PermMembersManage(c.persona)
		if c.table == "api_keys" {
			capability = PermCredentialsManage(c.persona)
		}
		err := s.authorizeRoleGrant(ctx, st, sch, c.persona, c.groupID, c.creator, capability, c.role)
		if err == nil {
			continue
		}
		if !errors.Is(err, ErrInsufficientRoleAuthority) && !errors.Is(err, ErrRoleAssignmentEscalation) && !errors.Is(err, ErrRoleNotAssignable) {
			return err
		}
		stamp := "revoked_at=now()"
		if c.table != "api_keys" {
			stamp += ", updated_at=now()"
		}
		if _, err := st.q.Exec(ctx, "UPDATE "+c.table+" SET "+stamp+" WHERE id=$1::uuid", c.id); err != nil {
			return err
		}
		revoked[c.id] = true
	}
	return nil
}

func (st *PermissionGroupStore) directRole(ctx context.Context, gid string, subject authkit.Subject) (authkit.Role, error) {
	table, column, err := groupRoleTable(subject.Kind)
	if err != nil {
		return "", err
	}
	var role authkit.Role
	err = st.q.QueryRow(ctx, fmt.Sprintf(`SELECT role FROM %s WHERE permission_group_id=$1::uuid AND %s=$2::uuid`, table, column), gid, subject.ID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return role, err
}

func subjectUsable(ctx context.Context, q db.DBTX, subject authkit.Subject) (bool, error) {
	var query string
	switch subject.Kind {
	case SubjectKindUser:
		query = `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1::uuid AND deleted_at IS NULL AND COALESCE(metadata->'reserved','false'::jsonb)<>'true'::jsonb AND ((banned_at IS NULL AND banned_until IS NULL AND ban_reason IS NULL AND banned_by IS NULL) OR banned_until<=statement_timestamp()))`
	case SubjectKindRemoteApp:
		query = `SELECT EXISTS(SELECT 1 FROM remote_applications a JOIN permission_groups g ON g.id=a.permission_group_id WHERE a.id=$1::uuid AND a.enabled AND g.deleted_at IS NULL)`
	default:
		return false, fmt.Errorf("invalid subject kind %q", subject.Kind)
	}
	var live bool
	err := q.QueryRow(ctx, query, subject.ID).Scan(&live)
	return live, err
}

// A request's verified native JWT authenticates its actor until expiry. Ban
// eligibility is checked at login/refresh, not added to each live permission
// mutation. Deleted/reserved identities remain invalid mutation actors. This
// is deliberately separate from the stricter current-owner eligibility above.
func authorizationActorPresent(ctx context.Context, q db.DBTX, userID string) (bool, error) {
	var present bool
	err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1::uuid AND deleted_at IS NULL AND COALESCE(metadata->'reserved','false'::jsonb)<>'true'::jsonb)`, userID).Scan(&present)
	return present, err
}

// refuseOwnerLoss checks a specific departing assignment, excluding its subject
// from the remaining live owners. Removing an already unusable principal does
// not create an ownership loss; empty bootstrap groups also remain possible.
func (s *engine) refuseOwnerLoss(ctx context.Context, st *PermissionGroupStore, gid string, subject authkit.Subject) error {
	role, err := st.directRole(ctx, gid, subject)
	if err != nil || role != OwnerRoleName {
		return err
	}
	live, err := subjectUsable(ctx, st.q, subject)
	if err == nil && live && subject.Kind == authkit.SubjectKindRemoteApp {
		err = st.q.QueryRow(ctx, `SELECT permission_group_id=$2::uuid FROM remote_applications WHERE id=$1::uuid`, subject.ID, gid).Scan(&live)
	}
	if err != nil || !live {
		return err
	}
	return s.requireRemainingOwner(ctx, st, gid, subject)
}

func (s *engine) requireRemainingOwner(ctx context.Context, st *PermissionGroupStore, gid string, excluding authkit.Subject) error {
	var persona authkit.Persona
	var inactive bool
	if err := st.q.QueryRow(ctx, `SELECT persona,deleted_at IS NOT NULL FROM permission_groups WHERE id=$1::uuid`, gid).Scan(&persona, &inactive); err != nil {
		return err
	}
	if inactive {
		return nil
	}
	owner, _ := s.groupSchemaOrDefault().Role(persona, OwnerRoleName)
	needsMFA := s.TwoFactorEnabled() && (s.requireMFAEnrollment() || owner.RequiresMFA)
	var remains bool
	err := st.q.QueryRow(ctx, `SELECT EXISTS(
 SELECT 1 FROM group_user_roles r JOIN users u ON u.id=r.user_id
 WHERE r.permission_group_id=$1::uuid AND r.role='owner' AND NOT ($2='user' AND u.id=$3::uuid)
 AND u.deleted_at IS NULL AND COALESCE(u.metadata->'reserved','false'::jsonb)<>'true'::jsonb AND ((u.banned_at IS NULL AND u.banned_until IS NULL AND u.ban_reason IS NULL AND u.banned_by IS NULL) OR u.banned_until<=statement_timestamp())
 AND (NOT $4 OR EXISTS(SELECT 1 FROM mfa_settings m WHERE m.user_id=u.id AND m.enabled
 AND EXISTS(SELECT 1 FROM mfa_factors f WHERE f.user_id=u.id)))
 UNION ALL
 SELECT 1 FROM group_remote_application_roles r JOIN remote_applications a ON a.id=r.remote_application_id
 WHERE r.permission_group_id=$1::uuid AND r.role='owner' AND NOT ($2='remote_application' AND a.id=$3::uuid) AND a.enabled AND a.permission_group_id=r.permission_group_id AND EXISTS(SELECT 1 FROM permission_groups control WHERE control.id=a.permission_group_id AND control.deleted_at IS NULL))`, gid, excluding.Kind, nullable(excluding.ID), needsMFA).Scan(&remains)
	if err != nil {
		return err
	}
	if !remains {
		return ErrCannotRemoveLastAdminRole
	}
	return nil
}

func (s *engine) refuseSubjectOwnerLoss(ctx context.Context, st *PermissionGroupStore, subject authkit.Subject) error {
	table, column, err := groupRoleTable(subject.Kind)
	if err != nil {
		return err
	}
	rows, err := st.q.Query(ctx, fmt.Sprintf(`SELECT permission_group_id::text FROM %s WHERE %s=$1::uuid AND role='owner' ORDER BY permission_group_id`, table, column), subject.ID)
	if err != nil {
		return err
	}
	var groups []string
	for rows.Next() {
		var gid string
		if err := rows.Scan(&gid); err != nil {
			rows.Close()
			return err
		}
		groups = append(groups, gid)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, gid := range groups {
		if err := s.refuseOwnerLoss(ctx, st, gid, subject); err != nil {
			return err
		}
	}
	return nil
}

// An invitation is a bounded bearer grant, not the inviter's current authority.
// Redemption can retain or increase its recipient's role, never strip grants.
func (s *engine) assignInvitedRole(ctx context.Context, st *PermissionGroupStore, gid string, persona authkit.Persona, userID string, role authkit.Role) error {
	subject := authkit.UserSubject(userID)
	old, err := st.directRole(ctx, gid, subject)
	if err != nil {
		return err
	}
	if old != "" && old != role {
		resolver, err := st.CustomRolesFor(ctx, []string{gid})
		if err != nil {
			return err
		}
		sch := s.groupSchemaOrDefault()
		oldGrants, err := s.roleGrantsForAuthz(sch, persona, gid, old, resolver)
		if err != nil {
			return err
		}
		offered, err := s.roleGrantsForAuthz(sch, persona, gid, role, resolver)
		if err != nil {
			return err
		}
		if !grantsCoverAll(offered, oldGrants) {
			return ErrRoleAssignmentEscalation
		}
		if err := s.refuseOwnerLoss(ctx, st, gid, subject); err != nil {
			return err
		}
	}
	if err := s.requireDefinedGroupRole(ctx, st, gid, persona, role); err != nil {
		return err
	}
	if err := s.requireMFAForRoleAssignment(ctx, st.q, gid, persona, subject, role); err != nil {
		return err
	}
	return st.AssignRole(ctx, gid, subject, role)
}

// A subtree deletion can also delete applications owning other groups. Check
// the surviving groups after all cascades, so departing apps cannot count one
// another as replacements. Caller already holds the authority transaction lock.
func outsideSubtreeApplicationOwnerGroups(ctx context.Context, st *PermissionGroupStore, gid string) ([]string, error) {
	rows, err := st.q.Query(ctx, `WITH RECURSIVE subtree AS (
      SELECT id FROM permission_groups WHERE id=$1::uuid
      UNION ALL SELECT g.id FROM permission_groups g JOIN subtree p ON g.parent_id=p.id)
      SELECT DISTINCT r.permission_group_id::text FROM group_remote_application_roles r
      JOIN remote_applications a ON a.id=r.remote_application_id
      WHERE a.permission_group_id IN (SELECT id FROM subtree) AND a.enabled AND r.role='owner'
      AND r.permission_group_id NOT IN (SELECT id FROM subtree)`, gid)
	if err != nil {
		return nil, err
	}
	var surviving []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		surviving = append(surviving, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return surviving, nil
}

func (s *engine) deleteGroupTx(ctx context.Context, st *PermissionGroupStore, gid string, opts authkit.DeletePermissionGroupOptions) error {
	surviving, err := outsideSubtreeApplicationOwnerGroups(ctx, st, gid)
	if err != nil {
		return err
	}
	if err := st.DeleteGroup(ctx, gid, opts); err != nil {
		return err
	}
	for _, id := range surviving {
		if err := s.requireRemainingOwner(ctx, st, id, authkit.Subject{}); err != nil {
			return err
		}
	}
	return nil
}
