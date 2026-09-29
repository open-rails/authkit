package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
)

// lockAuthority precedes every group, account, MFA and session row lock in an
// authority mutation. A schema-wide boundary also protects root grants and
// mutable role definitions. Login, verification and session reads do not use it.
func (s *Engine) lockAuthority(ctx context.Context, q db.DBTX) error {
	_, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "authkit.authority."+s.dbSchema())
	return err
}

// Authority reads after a queued lock must use a new statement snapshot even
// when a host configures its pool with a stronger default isolation level.
func (s *Engine) beginAuthorityTransaction(ctx context.Context) (pgx.Tx, error) {
	return s.pg.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
}

func (s *Engine) withAuthorityMutation(ctx context.Context, apply func(*permissionGroupStore) error) error {
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
// API keys, and deletes the roles of group-registered applications, whose
// issuer could no longer issue them, after grants in the touched groups
// changed (root grants apply in every group, so a root touch sweeps the whole
// site). A credential never outlives the authority that issued it; otherwise a
// demoted creator could redeem their own link, or keep using their own key or
// application, to regain the role. Operator-issued credentials (no creator)
// are swept only for MFA: no key or application holds a role that needs it.
func (s *Engine) revokeUncoveredCredentials(ctx context.Context, st *permissionGroupStore, touched ...authorityTouch) error {
	seen := map[authorityTouch]bool{}
	var creds []sweptCredential
	for _, t := range touched {
		if seen[t] {
			continue
		}
		seen[t] = true
		rows, err := st.q.Query(ctx, `WITH scope AS (
  SELECT g.id, g.persona FROM permission_groups t JOIN permission_groups g
    ON g.id=t.id OR (t.persona='root' AND g.deleted_at IS NULL)
   WHERE t.id=$1::uuid)
SELECT 'group_invite_links', l.id::text, l.permission_group_id::text, t.persona, l.role, l.invited_by::text, false
  FROM group_invite_links l JOIN scope t ON t.id=l.permission_group_id
 WHERE l.revoked_at IS NULL AND l.redeemed_at IS NULL AND (l.expires_at IS NULL OR l.expires_at>now())
   AND l.invited_by IS NOT NULL AND ($2::text='' OR l.invited_by=NULLIF($2::text,'')::uuid)
UNION ALL
SELECT 'account_registration_invites', a.id::text, a.permission_group_id::text, t.persona, a.role, a.invited_by::text, false
  FROM account_registration_invites a JOIN scope t ON t.id=a.permission_group_id
 WHERE a.revoked_at IS NULL AND a.consumed_at IS NULL AND a.expires_at>now()
   AND a.invited_by IS NOT NULL AND ($2::text='' OR a.invited_by=NULLIF($2::text,'')::uuid)
UNION ALL
SELECT 'account_registration_invites', a.id::text, t.id::text, t.persona, '', a.invited_by::text, false
  FROM account_registration_invites a JOIN scope t ON t.persona='root'
 WHERE a.permission_group_id IS NULL AND a.revoked_at IS NULL AND a.consumed_at IS NULL AND a.expires_at>now()
   AND a.invited_by IS NOT NULL AND ($2::text='' OR a.invited_by=NULLIF($2::text,'')::uuid)
UNION ALL
SELECT 'api_keys', k.id::text, k.permission_group_id::text, t.persona, k.role, COALESCE(k.created_by::text,''), false
  FROM api_keys k JOIN scope t ON t.id=k.permission_group_id
 WHERE k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at>now())
   AND ($2::text='' OR k.created_by=NULLIF($2::text,'')::uuid)
UNION ALL
SELECT 'group_remote_application_roles', a.id::text, r.permission_group_id::text, t.persona, r.role, COALESCE(a.registered_by::text,''), a.trust_root='user'
  FROM group_remote_application_roles r JOIN scope t ON t.id=r.permission_group_id
  JOIN remote_applications a ON a.id=r.remote_application_id
 WHERE ($2::text='' OR a.registered_by=NULLIF($2::text,'')::uuid)`, t.groupID, t.userID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var c sweptCredential
			if err := rows.Scan(&c.table, &c.id, &c.group.ID, &c.group.Persona, &c.role, &c.creator, &c.needsCreator); err != nil {
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
	revoked := map[string]bool{}
	for _, c := range creds {
		key := c.table + " " + c.group.ID + " " + c.id
		if revoked[key] {
			continue
		}
		stands, err := s.credentialStands(ctx, st, c)
		if err != nil || stands {
			if err != nil {
				return err
			}
			continue
		}
		if err := s.retireCredential(ctx, st, c); err != nil {
			return err
		}
		revoked[key] = true
	}
	return nil
}

// sweptCredential is one credential the sweep re-checks. For an application
// role, id is the application and group the group of the role.
type sweptCredential struct {
	table, id, creator string
	group              groupTarget
	role               iam.Role
	needsCreator       bool // a group registration: no registrar confers nothing
}

// credentialStands is rule CRED for c: its creator still issues it, and a key
// or application role never needs MFA.
func (s *Engine) credentialStands(ctx context.Context, st *permissionGroupStore, c sweptCredential) (bool, error) {
	machine := c.table == "api_keys" || c.table == "group_remote_application_roles"
	if machine && s.TwoFactorEnabled() {
		needsMFA, err := s.roleRequiresMFA(ctx, st.q, c.group.ID, c.group.Persona, c.role)
		if err != nil || needsMFA {
			return false, err
		}
	}
	if c.creator == "" {
		return !c.needsCreator, nil
	}
	capability := iam.PermMembersManage(c.group.Persona)
	switch {
	case machine:
		capability = iam.PermCredentialsManage(c.group.Persona)
	case c.role == "":
		capability = iam.PermRootUsersInvite
	}
	err := s.creatorCovers(ctx, st, c.creator, c.group, capability, c.role)
	if errors.Is(err, iam.ErrInsufficientAuthority) || errors.Is(err, iam.ErrRoleAssignmentEscalation) || errors.Is(err, iam.ErrRoleNotAssignable) {
		return false, nil
	}
	return err == nil, err
}

// retireCredential revokes c, or deletes an application's role. A change
// that strips the owner role of an application still counting as an owner
// (its live registrar lost cover) is refused like any other last-owner
// removal; a role that already conferred nothing (it needs MFA, or its
// registrar is gone) is no loss. The boot sweep never refuses: it retires and
// logs a group it leaves without a usable owner.
func (s *Engine) retireCredential(ctx context.Context, st *permissionGroupStore, c sweptCredential) error {
	if st.reconcile {
		slog.InfoContext(ctx, "authkit: role catalog changed; credential retired", "kind", c.table, "id", c.id, "group_id", c.group.ID, "role", c.role)
	}
	if c.table == "group_remote_application_roles" {
		app := iam.RemoteApplicationSubject(c.id)
		if c.role == iam.OwnerRole && !st.reconcile {
			if err := s.refuseOwnerLoss(ctx, st, c.group.ID, app); err != nil {
				return err
			}
		}
		if _, err := st.q.Exec(ctx, `DELETE FROM group_remote_application_roles WHERE permission_group_id=$1::uuid AND remote_application_id=$2::uuid`, c.group.ID, c.id); err != nil {
			return err
		}
		if c.role == iam.OwnerRole && st.reconcile {
			err := s.requireRemainingOwner(ctx, st, c.group.ID, iam.Subject{})
			if errors.Is(err, iam.ErrLastOwner) {
				slog.WarnContext(ctx, "authkit: the credential sweep left a group without a usable owner; assign one (Auth.OwnerlessGroups lists them)", "group_id", c.group.ID, "remote_application_id", c.id)
				return nil
			}
			return err
		}
		return nil
	}
	stamp := "revoked_at=now()"
	if c.table != "api_keys" {
		stamp += ", updated_at=now()"
	}
	_, err := st.q.Exec(ctx, "UPDATE "+c.table+" SET "+stamp+" WHERE id=$1::uuid", c.id)
	return err
}

// creatorCovers is rule CRED: the creator is still a live account (not
// banned, deleted or reserved), holds capability and covers role. A plain
// registration invite carries no role, so it needs capability only.
func (s *Engine) creatorCovers(ctx context.Context, st *permissionGroupStore, creator string, g groupTarget, capability iam.Perm, role iam.Role) error {
	if role == "" {
		auth, err := s.actorAuthority(ctx, st, iam.UserActor(creator), g)
		if err != nil {
			return err
		}
		return auth.requireCap(capability)
	}
	return s.requireRoleGrant(ctx, st, iam.UserActor(creator), g, capability, role)
}

// revokeCredentialsOf re-checks every live API key, invite link and
// registration invite userID issued, in every group, and revokes those it no
// longer covers. Account lifecycle paths (ban, soft delete, reserve, and purge
// before the row goes) call it inside their authority transaction; after any
// of them the user covers nothing.
func (s *Engine) revokeCredentialsOf(ctx context.Context, st *permissionGroupStore, userID string) error {
	rootID, err := s.rootGroup(ctx, st)
	if err != nil {
		return err
	}
	return s.revokeUncoveredCredentials(ctx, st, authorityTouch{groupID: rootID, userID: userID})
}

func (st *permissionGroupStore) directRole(ctx context.Context, gid string, subject iam.Subject) (iam.Role, error) {
	table, column, err := groupRoleTable(subject.Kind)
	if err != nil {
		return "", err
	}
	var role iam.Role
	err = st.q.QueryRow(ctx, fmt.Sprintf(`SELECT role FROM %s WHERE permission_group_id=$1::uuid AND %s=$2::uuid`, table, column), gid, subject.ID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return role, err
}

func subjectUsable(ctx context.Context, q db.DBTX, subject iam.Subject) (bool, error) {
	var query string
	switch subject.Kind {
	case iam.SubjectKindUser:
		query = `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1::uuid AND deleted_at IS NULL AND COALESCE(metadata->'reserved','false'::jsonb)<>'true'::jsonb AND ((banned_at IS NULL AND banned_until IS NULL AND ban_reason IS NULL AND banned_by IS NULL) OR banned_until<=statement_timestamp()))`
	case iam.SubjectKindRemoteApplication:
		query = `SELECT EXISTS(SELECT 1 FROM remote_applications a JOIN permission_groups g ON g.id=a.permission_group_id WHERE a.id=$1::uuid AND a.enabled AND g.deleted_at IS NULL AND ` + registrarLive("a") + `)`
	default:
		return false, fmt.Errorf("invalid subject kind %q", subject.Kind)
	}
	var live bool
	err := q.QueryRow(ctx, query, subject.ID).Scan(&live)
	return live, err
}

// refuseOwnerLoss checks a specific departing assignment, excluding its subject
// from the remaining live owners. Removing a principal that does not count as
// an owner (unusable, or an application where owners need MFA) creates no
// ownership loss; empty bootstrap groups also remain possible.
func (s *Engine) refuseOwnerLoss(ctx context.Context, st *permissionGroupStore, gid string, subject iam.Subject) error {
	role, err := st.directRole(ctx, gid, subject)
	if err != nil || role != iam.OwnerRole {
		return err
	}
	live, err := subjectUsable(ctx, st.q, subject)
	if err == nil && live && subject.Kind == iam.SubjectKindRemoteApplication {
		var persona iam.Persona
		err = st.q.QueryRow(ctx, `SELECT a.permission_group_id=$2::uuid, g.persona FROM remote_applications a JOIN permission_groups g ON g.id=$2::uuid WHERE a.id=$1::uuid`, subject.ID, gid).Scan(&live, &persona)
		live = live && !s.ownersNeedMFA(persona)
	}
	if err != nil || !live {
		return err
	}
	return s.requireRemainingOwner(ctx, st, gid, subject)
}

// ownersNeedMFA reports whether only MFA-enrolled users count as owners of a
// persona's groups; applications then never do.
func (s *Engine) ownersNeedMFA(persona iam.Persona) bool {
	owner, _ := s.groupSchemaOrDefault().Role(persona, iam.OwnerRole)
	return s.TwoFactorEnabled() && (s.requireMFAEnrollment() || owner.RequiresMFA)
}

func (s *Engine) requireRemainingOwner(ctx context.Context, st *permissionGroupStore, gid string, excluding iam.Subject) error {
	var persona iam.Persona
	var inactive bool
	if err := st.q.QueryRow(ctx, `SELECT persona,deleted_at IS NOT NULL FROM permission_groups WHERE id=$1::uuid`, gid).Scan(&persona, &inactive); err != nil {
		return err
	}
	if inactive {
		return nil
	}
	var remains bool
	err := st.q.QueryRow(ctx, `SELECT `+usableOwner("$1::uuid", "$2::text", "$3::uuid", "$4::bool"), gid, string(excluding.Kind), nullable(excluding.ID), s.ownersNeedMFA(persona)).Scan(&remains)
	if err != nil {
		return err
	}
	if !remains {
		return iam.ErrLastOwner
	}
	return nil
}

// usableOwner is a SQL predicate: group gid has an owner that counts, other
// than the subject (kind, id): a live user, MFA-enrolled when needsMFA, or,
// when owners need no MFA, an enabled application of the group itself whose
// registrar is live. An application a departing user registered never stands
// in for that user: its authority ends with theirs (R1).
func usableOwner(gid, kind, id, needsMFA string) string {
	return `EXISTS(
 SELECT 1 FROM group_user_roles r JOIN users u ON u.id=r.user_id
 WHERE r.permission_group_id=` + gid + ` AND r.role='owner' AND NOT (` + kind + `='user' AND u.id=` + id + `)
 AND u.deleted_at IS NULL AND COALESCE(u.metadata->'reserved','false'::jsonb)<>'true'::jsonb AND ((u.banned_at IS NULL AND u.banned_until IS NULL AND u.ban_reason IS NULL AND u.banned_by IS NULL) OR u.banned_until<=statement_timestamp())
 AND (NOT ` + needsMFA + ` OR EXISTS(SELECT 1 FROM mfa_settings m WHERE m.user_id=u.id AND m.enabled
 AND EXISTS(SELECT 1 FROM mfa_factors f WHERE f.user_id=u.id)))
 UNION ALL
 SELECT 1 FROM group_remote_application_roles r JOIN remote_applications a ON a.id=r.remote_application_id
 WHERE NOT ` + needsMFA + ` AND r.permission_group_id=` + gid + ` AND r.role='owner' AND NOT (` + kind + `='remote_application' AND a.id=` + id + `)
 AND NOT (` + kind + `='user' AND a.registered_by IS NOT DISTINCT FROM ` + id + `)
 AND a.enabled AND a.permission_group_id=r.permission_group_id AND ` + registrarLive("a") + ` AND EXISTS(SELECT 1 FROM permission_groups control WHERE control.id=a.permission_group_id AND control.deleted_at IS NULL))`
}

func (s *Engine) refuseSubjectOwnerLoss(ctx context.Context, st *permissionGroupStore, subject iam.Subject) error {
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
func (s *Engine) assignInvitedRole(ctx context.Context, st *permissionGroupStore, gid string, persona iam.Persona, userID string, role iam.Role) error {
	subject := iam.UserSubject(userID)
	old, err := st.directRole(ctx, gid, subject)
	if err != nil {
		return err
	}
	if old != "" && old != role {
		g := groupTarget{ID: gid, Persona: persona}
		oldGrants, err := s.roleGrants(ctx, st, g, old)
		if err != nil {
			return err
		}
		offered, err := s.roleGrants(ctx, st, g, role)
		if err != nil {
			return err
		}
		if !grantsCoverAll(offered, oldGrants) {
			return iam.ErrRoleAssignmentEscalation
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

// A group deletion can also delete applications owning other groups. Check
// the surviving groups after all cascades, so departing apps cannot count one
// another as replacements. Caller already holds the authority transaction lock.
func outsideApplicationOwnerGroups(ctx context.Context, st *permissionGroupStore, gid string) ([]string, error) {
	rows, err := st.q.Query(ctx, `SELECT DISTINCT r.permission_group_id::text FROM group_remote_application_roles r
      JOIN remote_applications a ON a.id=r.remote_application_id
      WHERE a.permission_group_id=$1::uuid AND a.enabled AND r.role='owner'
      AND r.permission_group_id<>$1::uuid`, gid)
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

func (s *Engine) deleteGroupTx(ctx context.Context, st *permissionGroupStore, gid string, opts iam.PurgeGroupOptions) error {
	surviving, err := outsideApplicationOwnerGroups(ctx, st, gid)
	if err != nil {
		return err
	}
	if err := st.DeleteGroup(ctx, gid, opts); err != nil {
		return err
	}
	for _, id := range surviving {
		if err := s.requireRemainingOwner(ctx, st, id, iam.Subject{}); err != nil {
			return err
		}
	}
	return nil
}
