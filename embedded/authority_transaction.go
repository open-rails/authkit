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
	return tx.Commit(ctx)
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
		query = `SELECT EXISTS(SELECT 1 FROM remote_applications WHERE id=$1::uuid AND enabled)`
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
	if err != nil || !live {
		return err
	}
	return s.requireRemainingOwner(ctx, st, gid, subject)
}

func (s *engine) requireRemainingOwner(ctx context.Context, st *PermissionGroupStore, gid string, excluding authkit.Subject) error {
	var persona authkit.Persona
	if err := st.q.QueryRow(ctx, `SELECT persona FROM permission_groups WHERE id=$1::uuid`, gid).Scan(&persona); err != nil {
		return err
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
 WHERE r.permission_group_id=$1::uuid AND r.role='owner' AND NOT ($2='remote_application' AND a.id=$3::uuid) AND a.enabled)`, gid, excluding.Kind, nullable(excluding.ID), needsMFA).Scan(&remains)
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
func (s *engine) deleteGroupTx(ctx context.Context, st *PermissionGroupStore, gid string, opts authkit.DeletePermissionGroupOptions) error {
	rows, err := st.q.Query(ctx, `WITH RECURSIVE subtree AS (
      SELECT id FROM permission_groups WHERE id=$1::uuid
      UNION ALL SELECT g.id FROM permission_groups g JOIN subtree p ON g.parent_id=p.id)
      SELECT DISTINCT r.permission_group_id::text FROM group_remote_application_roles r
      JOIN remote_applications a ON a.id=r.remote_application_id
      WHERE a.permission_group_id IN (SELECT id FROM subtree) AND a.enabled AND r.role='owner'
      AND r.permission_group_id NOT IN (SELECT id FROM subtree)`, gid)
	if err != nil {
		return err
	}
	var surviving []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		surviving = append(surviving, id)
	}
	err = rows.Err()
	rows.Close()
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
