package engine

// DB-backed engine for the permission-group model (#111): the store loads the
// subject's assignments on a target group and on root, and feeds the pure
// decision core (rbac.Schema.Can). Hand-written over db.DBTX (pool or tx)
// so it composes with the engine's schema-bound pool exactly like the
// generated queries; unqualified table names resolve through the
// schema-bound AuthKit pool (authkit #69).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/rbac"
)

func groupRoleTable(kind iam.SubjectKind) (table, subjectColumn string, err error) {
	switch kind {
	case iam.SubjectKindUser:
		return "group_user_roles", "user_id", nil
	case iam.SubjectKindRemoteApplication:
		return "group_remote_application_roles", "remote_application_id", nil
	default:
		return "", "", fmt.Errorf("invalid group subject kind %q", kind)
	}
}

// PermissionGroupStore is the database access layer for permission-groups. It
// holds a db.DBTX (a *pgxpool.Pool or a pgx.Tx), so callers choose the txn scope.
type permissionGroupStore struct {
	q   db.DBTX
	now func() time.Time
	// touched records authority reductions for the enclosing authority
	// mutation, which revokes credentials their creators no longer cover.
	touched []authorityTouch
}

// authorityTouch names a group whose grants changed, and the user whose
// authority changed ("" = every holder of an edited role).
type authorityTouch struct{ groupID, userID string }

func (st *permissionGroupStore) touch(groupID string, subject iam.Subject) {
	if subject.Kind == iam.SubjectKindUser {
		st.touched = append(st.touched, authorityTouch{groupID, subject.ID})
	}
}

// NewPermissionGroupStore wraps a db.DBTX (pool or transaction).
func newPermissionGroupStore(q db.DBTX) *permissionGroupStore {
	return &permissionGroupStore{q: q, now: time.Now}
}

// CreateGroupNamed inserts a non-root permission group with a first-class
// display name (#264): free-form, non-unique vanity metadata (the slug stays
// the unique handle). It returns the group's internal id.
func (st *permissionGroupStore) CreateGroupNamed(ctx context.Context, g iam.GroupRef, displayName string) (string, error) {
	var id string
	err := st.q.QueryRow(ctx,
		`WITH identity AS MATERIALIZED (SELECT uuidv7() AS id),
         claim AS MATERIALIZED (SELECT id, claim_canonical_name('group',$1,$2,id,$4) FROM identity)
         INSERT INTO permission_groups (id,persona,instance_slug,display_name)
         SELECT id,$1,$2,$3 FROM claim RETURNING id::text`,
		g.Persona(), g.Slug(), displayName, st.now()).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create %q group: %w", g.Persona(), nameClaimError(err, "group"))
	}
	return id, nil
}

// SetGroupDisplayName updates a group's free-form display name.
func (st *permissionGroupStore) SetGroupDisplayName(ctx context.Context, groupID, displayName string) error {
	tag, err := st.q.Exec(ctx,
		`UPDATE permission_groups SET display_name = $2 WHERE id = $1::uuid AND deleted_at IS NULL`,
		groupID, displayName)
	if err == nil && tag.RowsAffected() == 0 {
		return iam.ErrGroupNotFound
	}
	return err
}

// lockGroup serializes lifecycle changes with renames. The root group cannot
// be deleted.
func (st *permissionGroupStore) lockGroup(ctx context.Context, groupID string) error {
	var persona iam.Persona
	err := st.q.QueryRow(ctx, `SELECT persona FROM permission_groups WHERE id=$1::uuid FOR UPDATE`, groupID).Scan(&persona)
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.ErrGroupNotFound
	}
	if err != nil {
		return err
	}
	if persona == iam.RootPersona {
		return fmt.Errorf("the root group cannot be deleted: %w", iam.ErrUnknownGroupPersona)
	}
	return nil
}

func (st *permissionGroupStore) DeleteGroup(ctx context.Context, groupID string, opts iam.DeletePermissionGroupOptions) error {
	if err := st.lockGroup(ctx, groupID); err != nil {
		return err
	}
	if !opts.ReleaseSlug {
		if _, err := st.q.Exec(ctx, `UPDATE name_claims SET canonical=false,expires_at=NULL WHERE owner_kind='group' AND owner_id=$1::uuid AND canonical`, groupID); err != nil {
			return err
		}
	}
	_, err := st.q.Exec(ctx, `DELETE FROM permission_groups WHERE id=$1::uuid`, groupID)
	return err
}

// InstanceSlugAvailable applies exactly the resolver's request-time expiry rule.
func (st *permissionGroupStore) InstanceSlugAvailable(ctx context.Context, g iam.GroupRef) (bool, error) {
	var available bool
	err := st.q.QueryRow(ctx, `SELECT NOT EXISTS (SELECT 1 FROM name_claims WHERE owner_kind='group' AND persona=$1 AND name=lower($2) AND (canonical OR expires_at IS NULL OR expires_at>$3))`, g.Persona(), g.Slug(), st.now()).Scan(&available)
	return available, err
}

// RenameGroupSlug requires the group owner row locked in the caller transaction.
// It reads the outgoing spelling again rather than trusting a route's old alias.
func (st *permissionGroupStore) renameGroupSlug(ctx context.Context, groupID, newSlug string, policy iam.NamingPolicy) error {
	var persona string
	var old *string
	var last *time.Time
	err := st.q.QueryRow(ctx, `SELECT persona,instance_slug,last_renamed_at FROM permission_groups WHERE id=$1::uuid AND deleted_at IS NULL FOR UPDATE`, groupID).Scan(&persona, &old, &last)
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.ErrGroupNotFound
	}
	if err != nil {
		return err
	}
	if old != nil && *old == newSlug {
		return nil
	}
	now := st.now()
	if err := policy.CheckRename(last, now); err != nil {
		return err
	}
	oldName := ""
	if old != nil {
		oldName = *old
	}
	if err := renameNameClaim(ctx, st.q, "group", persona, groupID, oldName, newSlug, now, policy); err != nil {
		return err
	}
	_, err = st.q.Exec(ctx, `UPDATE permission_groups SET instance_slug=$2,last_renamed_at=$3 WHERE id=$1::uuid`, groupID, newSlug, now)
	return err
}

func (st *permissionGroupStore) ResolveGroupSlug(ctx context.Context, g iam.GroupRef) (iam.NameResolution, error) {
	var out iam.NameResolution
	err := st.q.QueryRow(ctx, `SELECT g.id::text,g.instance_slug,NOT c.canonical,c.expires_at FROM name_claims c JOIN permission_groups g ON g.id=c.owner_id WHERE g.deleted_at IS NULL AND c.owner_kind='group' AND c.persona=$1 AND c.name=lower($2) AND (c.canonical OR c.expires_at IS NULL OR c.expires_at>$3)`, g.Persona(), g.Slug(), st.now()).Scan(&out.ID, &out.CanonicalName, &out.IsAlias, &out.AliasExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, iam.ErrGroupNotFound
	}
	return out, err
}

func (st *permissionGroupStore) GroupByInstanceSlug(ctx context.Context, g iam.GroupRef) (string, error) {
	if id, bound, err := st.requestGroupID(ctx, g); bound {
		return id, err
	}
	out, err := st.ResolveGroupSlug(ctx, g)
	return out.ID, err
}

// GroupByLiveInstanceSlug resolves (persona, instance_slug) WITHOUT tombstone
// forwarding — the group currently holding the slug, or ErrGroupNotFound.
func (st *permissionGroupStore) GroupByLiveInstanceSlug(ctx context.Context, g iam.GroupRef) (string, error) {
	var id string
	err := st.q.QueryRow(ctx,
		`SELECT id::text FROM permission_groups
		 WHERE persona = $1 AND instance_slug = $2 AND deleted_at IS NULL`,
		g.Persona(), g.Slug()).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", iam.ErrGroupNotFound
	}
	if err != nil {
		return "", err
	}
	return id, nil
}

// RootGroupID returns the singleton root group's internal id (ErrGroupNotFound
// if the deployment has not seeded one yet).
func (st *permissionGroupStore) RootGroupID(ctx context.Context) (string, error) {
	var id string
	err := st.q.QueryRow(ctx,
		`SELECT id::text FROM permission_groups WHERE persona = 'root'`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", iam.ErrGroupNotFound
	}
	return id, err
}

// WalkAssignments returns the subject's assignments on the target group and on
// root: exactly what rbac.Schema.ResolveGrants/Can consume.
func (st *permissionGroupStore) WalkAssignments(ctx context.Context, groupID string, subject iam.Subject) ([]rbac.Assignment, error) {
	assignments, _, err := st.assignmentsWithCustomRoles(ctx, groupID, subject, false)
	return assignments, err
}

// Memberships and their mutable custom definitions come from one MVCC snapshot.
// A delete/recreate cannot combine a retired membership with the replacement
// role's permissions. Include all definitions on assigned groups, preserving
// the existing authorization resolver's scope for target-role checks.
func (st *permissionGroupStore) assignmentsWithCustomRoles(ctx context.Context, groupID string, subject iam.Subject, definitions bool) ([]rbac.Assignment, rbac.CustomRoleResolver, error) {
	return st.readAssignments(ctx, groupID, subject, definitions, false)
}

// Authorization excludes deleted/reserved native accounts in the same MVCC
// query. Ban freshness is separate. Introspection and no-escalation comparisons
// must retain latent assignments, including those of a deleted target.
func (st *permissionGroupStore) readAssignments(ctx context.Context, groupID string, subject iam.Subject, definitions, requirePresentUser bool) ([]rbac.Assignment, rbac.CustomRoleResolver, error) {
	byGroup, resolver, err := st.readAssignmentsForGroups(ctx, []string{groupID}, subject, definitions, requirePresentUser)
	if err != nil {
		return nil, nil, err
	}
	return byGroup[groupID], resolver, nil
}

// readAssignmentsForGroups reads, for every live target, the subject's
// assignments on that group and on root, in one query. Deleted, unknown and
// malformed targets have no assignments.
func (st *permissionGroupStore) readAssignmentsForGroups(ctx context.Context, groupIDs []string, subject iam.Subject, definitions, requirePresentUser bool) (map[string][]rbac.Assignment, rbac.CustomRoleResolver, error) {
	table, column, err := groupRoleTable(subject.Kind)
	if err != nil {
		return nil, nil, err
	}
	type key struct {
		group string
		role  iam.Role
	}
	custom := map[key][]string{}
	resolver := func(group string, role iam.Role) ([]string, bool) {
		p, ok := custom[key{group, role}]
		return p, ok
	}
	out := map[string][]rbac.Assignment{}
	ids := groupBatchIDs(groupIDs)
	if len(ids) == 0 {
		return out, resolver, nil
	}
	rows, err := st.q.Query(ctx, fmt.Sprintf(`WITH targets AS (
 SELECT id,persona FROM permission_groups WHERE id=ANY($1::uuid[]) AND deleted_at IS NULL),
 chain AS (SELECT id AS target,id,persona FROM targets
 UNION SELECT t.id,rg.id,rg.persona FROM targets t JOIN permission_groups rg ON rg.persona='root')
 SELECT c.target::text,c.id::text,c.persona,a.role,r.role,r.permissions FROM chain c
 JOIN %s a ON a.permission_group_id=c.id AND a.%s=$2::uuid
 LEFT JOIN group_custom_roles r ON r.permission_group_id=c.id AND $3
 WHERE (NOT $4 OR EXISTS(SELECT 1 FROM users actor WHERE actor.id=$2::uuid
 AND actor.deleted_at IS NULL AND COALESCE(actor.metadata->'reserved','false'::jsonb)<>'true'::jsonb))
 AND ($5 <> 'remote_application' OR EXISTS(SELECT 1 FROM remote_applications actor JOIN permission_groups control ON control.id=actor.permission_group_id WHERE actor.id=$2::uuid AND actor.enabled AND control.deleted_at IS NULL))
 ORDER BY c.target,c.id,r.role`, table, column), ids, subject.ID, definitions, requirePresentUser, subject.Kind)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	seen := map[[2]string]bool{}
	for rows.Next() {
		var target string
		var assignment rbac.Assignment
		var role *string
		var permissions []string
		if err := rows.Scan(&target, &assignment.PermissionGroupID, &assignment.Persona, &assignment.Role, &role, &permissions); err != nil {
			return nil, nil, err
		}
		if k := [2]string{target, assignment.PermissionGroupID}; !seen[k] {
			seen[k] = true
			out[target] = append(out[target], assignment)
		}
		if role != nil {
			custom[key{assignment.PermissionGroupID, iam.Role(*role)}] = permissions
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return out, resolver, nil
}

// groupBatchIDs keeps distinct canonical UUIDs; anything else cannot name a group.
func groupBatchIDs(ids []string) []string {
	out := make([]string, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if u, err := uuid.Parse(id); err != nil || u.String() != id || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// RootRolesForUsers returns, for each user id, the role slugs directly assigned on
// the root group (rootGID), batching a whole page's lookups into one query (the
// admin-directory enrichment path; avoids a per-row N+1).
func (st *permissionGroupStore) RootRolesForUsers(ctx context.Context, rootGID string, userIDs []string) (map[string][]string, error) {
	out := make(map[string][]string, len(userIDs))
	if len(userIDs) == 0 {
		return out, nil
	}
	rows, err := st.q.Query(ctx,
		`SELECT user_id::text, role FROM group_user_roles
		 WHERE permission_group_id = $1::uuid AND user_id = ANY($2::uuid[])`,
		rootGID, userIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var uid, role string
		if err := rows.Scan(&uid, &role); err != nil {
			return nil, err
		}
		out[uid] = append(out[uid], role)
	}
	return out, rows.Err()
}

// AssignRole replaces the current role for a group and subject. The composite
// primary key enforces one assignment; callers validate the role definition.
func (st *permissionGroupStore) AssignRole(ctx context.Context, groupID string, subject iam.Subject, role iam.Role) error {
	if subject.Kind == iam.SubjectKindRemoteApplication && role == iam.OwnerRole {
		var operable bool
		if err := st.q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM remote_applications WHERE id=$1::uuid AND enabled AND permission_group_id=$2::uuid)`, subject.ID, groupID).Scan(&operable); err != nil {
			return err
		}
		if !operable {
			return iam.ErrInsufficientRoleAuthority
		}
	}
	table, subjectColumn, err := groupRoleTable(subject.Kind)
	if err != nil {
		return err
	}
	tag, err := st.q.Exec(ctx, fmt.Sprintf(`WITH locked AS MATERIALIZED (SELECT id FROM permission_groups WHERE id=$1::uuid AND deleted_at IS NULL FOR UPDATE)
 INSERT INTO %s (permission_group_id, %s, role)
 SELECT id, $2::uuid, $3 FROM locked
 ON CONFLICT (permission_group_id, %s)
 DO UPDATE SET role=EXCLUDED.role`, table, subjectColumn, subjectColumn), groupID, subject.ID, role)
	if err == nil && tag.RowsAffected() == 0 {
		return iam.ErrGroupNotFound
	}
	if err == nil {
		st.touch(groupID, subject)
	}
	return err
}

// UnassignRole deletes the matching current assignment.
func (st *permissionGroupStore) UnassignRole(ctx context.Context, groupID string, subject iam.Subject, role iam.Role) error {
	table, subjectColumn, err := groupRoleTable(subject.Kind)
	if err != nil {
		return err
	}
	_, err = st.q.Exec(ctx,
		fmt.Sprintf(`DELETE FROM %s
		 WHERE permission_group_id = $1::uuid AND %s = $2::uuid AND role = $3`,
			table, subjectColumn),
		groupID, subject.ID, role)
	st.touch(groupID, subject)
	return err
}

// UnassignSubject deletes the subject's current assignment in this group.
func (st *permissionGroupStore) UnassignSubject(ctx context.Context, groupID string, subject iam.Subject) error {
	table, subjectColumn, err := groupRoleTable(subject.Kind)
	if err != nil {
		return err
	}
	_, err = st.q.Exec(ctx,
		fmt.Sprintf(`DELETE FROM %s
		 WHERE permission_group_id = $1::uuid AND %s = $2::uuid`, table, subjectColumn),
		groupID, subject.ID)
	st.touch(groupID, subject)
	return err
}

// OwnerCount returns the count of live, unbanned, unreserved user owners and
// enabled application owners. Lifecycle safety uses the transaction-bound
// engine guard, which also checks the deployment's MFA policy.
func (st *permissionGroupStore) OwnerCount(ctx context.Context, groupID string) (int, error) {
	var n int
	err := st.q.QueryRow(ctx, `SELECT
    (SELECT count(*) FROM group_user_roles r JOIN users u ON u.id=r.user_id
     WHERE r.permission_group_id=$1::uuid AND r.role='owner' AND u.deleted_at IS NULL
     AND COALESCE(u.metadata->'reserved','false'::jsonb)<>'true'::jsonb
     AND ((u.banned_at IS NULL AND u.banned_until IS NULL AND u.ban_reason IS NULL AND u.banned_by IS NULL) OR u.banned_until<=statement_timestamp()))
    + (SELECT count(*) FROM group_remote_application_roles r JOIN remote_applications a ON a.id=r.remote_application_id
       WHERE r.permission_group_id=$1::uuid AND r.role='owner' AND a.enabled AND a.permission_group_id=r.permission_group_id)`, groupID).Scan(&n)
	return n, err
}

// UpsertCustomRole defines/updates a per-group custom role's permission set and
// its requires_mfa flag (#247). Only meaningful for personas whose CustomRoles
// capability is set; the caller enforces that + validates each grant pattern
// against the group's persona.
func (st *permissionGroupStore) UpsertCustomRole(ctx context.Context, groupID string, def authflow.CustomRoleDef) error {
	tag, err := st.q.Exec(ctx, `WITH locked AS MATERIALIZED (SELECT id FROM permission_groups WHERE id=$1::uuid AND deleted_at IS NULL FOR UPDATE)
 INSERT INTO group_custom_roles(permission_group_id,role,permissions,requires_mfa)
 SELECT id,$2,$3,$4 FROM locked
 ON CONFLICT(permission_group_id,role) DO UPDATE SET permissions=EXCLUDED.permissions,requires_mfa=EXCLUDED.requires_mfa,updated_at=now()`, groupID, def.Role, def.Permissions, def.RequiresMFA)
	if err == nil && tag.RowsAffected() == 0 {
		return iam.ErrGroupNotFound
	}
	if err == nil {
		st.touched = append(st.touched, authorityTouch{groupID: groupID})
	}
	return err
}

// CustomRole returns a single per-group custom role's stored permissions and
// requires_mfa flag, or (nil, false, nil) if no such custom role is defined —
// absence is not an error (the caller may be about to CREATE it).
func (st *permissionGroupStore) CustomRole(ctx context.Context, groupID string, role iam.Role) (permissions []string, requiresMFA bool, err error) {
	err = st.q.QueryRow(ctx,
		`SELECT permissions, requires_mfa FROM group_custom_roles
		 WHERE permission_group_id = $1::uuid AND role = $2`,
		groupID, role).Scan(&permissions, &requiresMFA)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	return permissions, requiresMFA, err
}

// CustomRolesFor preloads the custom roles for a set of group ids and returns a
// CustomRoleResolver backed by the result — so the pure decision core resolves
// custom-role grants without per-call DB access.
func (st *permissionGroupStore) CustomRolesFor(ctx context.Context, groupIDs []string) (rbac.CustomRoleResolver, error) {
	if len(groupIDs) == 0 {
		return func(string, iam.Role) ([]string, bool) { return nil, false }, nil
	}
	rows, err := st.q.Query(ctx,
		`SELECT permission_group_id::text, role, permissions FROM group_custom_roles
		 WHERE permission_group_id = ANY($1::uuid[])`,
		groupIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type key struct {
		g string
		r iam.Role
	}
	m := map[key][]string{}
	for rows.Next() {
		var gid string
		var role iam.Role
		var perms []string
		if err := rows.Scan(&gid, &role, &perms); err != nil {
			return nil, err
		}
		m[key{gid, role}] = perms
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return func(groupID string, role iam.Role) ([]string, bool) {
		p, ok := m[key{groupID, role}]
		return p, ok
	}, nil
}

// CanOnGroup is the end-to-end DB-backed authorization check: read the
// subject's roles on the target group and on root, preload any custom roles,
// and test perm coverage against the schema.
func (st *permissionGroupStore) CanOnGroup(ctx context.Context, schema *rbac.Schema, subject iam.Subject, groupID string, perm iam.Perm) (bool, error) {
	assignments, resolver, err := st.readAssignments(ctx, groupID, subject, true, subject.Kind == iam.SubjectKindUser)
	if err != nil {
		return false, err
	}
	return schema.Can(groupID, assignments, resolver, perm), nil
}

// GrantsOnGroups returns, per live target group, the de-duplicated UNION of
// grant PATTERNS the subject holds on that group and on root, resolved
// against the schema's catalog + per-group custom roles, in one query. Globs
// like `root:*` are returned verbatim, not expanded. Targets granting nothing
// are absent. Latent assignments of deleted/reserved accounts are included.
func (st *permissionGroupStore) GrantsOnGroups(ctx context.Context, schema *rbac.Schema, subject iam.Subject, groupIDs []string) (map[string][]string, error) {
	byGroup, resolver, err := st.readAssignmentsForGroups(ctx, groupIDs, subject, true, false)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(byGroup))
	for gid, assignments := range byGroup {
		if grants := schema.ResolveGrants(gid, assignments, resolver); len(grants) > 0 {
			out[gid] = grants
		}
	}
	return out, nil
}

// GrantsOnGroup is GrantsOnGroups for one group; no grants is an empty slice.
func (st *permissionGroupStore) GrantsOnGroup(ctx context.Context, schema *rbac.Schema, subject iam.Subject, groupID string) ([]string, error) {
	grants, err := st.GrantsOnGroups(ctx, schema, subject, []string{groupID})
	if err != nil {
		return nil, err
	}
	if g := grants[groupID]; g != nil {
		return g, nil
	}
	return []string{}, nil
}

// GroupMembers lists the live role-assignments in a group.
func (st *permissionGroupStore) GroupMembers(ctx context.Context, groupID string) ([]iam.GroupMember, error) {
	rows, err := st.q.Query(ctx,
		`SELECT user_id::text, 'user' AS subject_kind, role FROM group_user_roles
		 WHERE permission_group_id = $1::uuid
		 UNION ALL
		 SELECT remote_application_id::text, 'remote_application' AS subject_kind, role
		   FROM group_remote_application_roles
		  WHERE permission_group_id = $1::uuid
		 ORDER BY 1, 3`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []iam.GroupMember
	for rows.Next() {
		var m iam.GroupMember
		if err := rows.Scan(&m.SubjectID, &m.SubjectKind, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// SubjectGroups lists every group membership a subject holds (cross-persona),
// the data behind /me/groups.
func (st *permissionGroupStore) SubjectGroups(ctx context.Context, subject iam.Subject) ([]iam.SubjectGroupMembership, error) {
	table, subjectColumn, err := groupRoleTable(subject.Kind)
	if err != nil {
		return nil, err
	}
	rows, err := st.q.Query(ctx,
		fmt.Sprintf(`SELECT g.id::text, g.persona, COALESCE(g.instance_slug, ''), g.display_name, a.role
		 FROM %s a
		 JOIN permission_groups g ON g.id = a.permission_group_id
		 WHERE a.%s = $1::uuid AND g.deleted_at IS NULL
		 ORDER BY g.persona, g.instance_slug, a.role`, table, subjectColumn), subject.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []iam.SubjectGroupMembership
	for rows.Next() {
		var m iam.SubjectGroupMembership
		if err := rows.Scan(&m.GroupID, &m.Persona, &m.InstanceSlug, &m.DisplayName, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// GroupInstancesByIDs reads many groups' own identity rows (#269), including
// retained soft-deleted ones (DeletedAt set), in one query. Unknown and
// malformed ids are absent. Ids are ones the caller already resolved.
func (st *permissionGroupStore) GroupInstancesByIDs(ctx context.Context, groupIDs []string) (map[string]iam.GroupInstance, error) {
	out := map[string]iam.GroupInstance{}
	ids := groupBatchIDs(groupIDs)
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := st.q.Query(ctx,
		`SELECT id::text, persona, COALESCE(instance_slug, ''), COALESCE(display_name, ''), deleted_at
		   FROM permission_groups WHERE id = ANY($1::uuid[])`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var g iam.GroupInstance
		if err := rows.Scan(&g.ID, &g.Persona, &g.InstanceSlug, &g.DisplayName, &g.DeletedAt); err != nil {
			return nil, err
		}
		out[g.ID] = g
	}
	return out, rows.Err()
}

// GroupInstanceByID is GroupInstancesByIDs for one id; absence is ErrGroupNotFound.
func (st *permissionGroupStore) GroupInstanceByID(ctx context.Context, groupID string) (iam.GroupInstance, error) {
	groups, err := st.GroupInstancesByIDs(ctx, []string{groupID})
	if err != nil {
		return iam.GroupInstance{}, err
	}
	g, ok := groups[groupID]
	if !ok {
		return iam.GroupInstance{}, iam.ErrGroupNotFound
	}
	return g, nil
}

// DeleteCustomRole retires a definition and every reference to it. The caller
// must hold the group lifecycle lock in a transaction. An absent definition is
// a no-op, so a catalog role cannot accidentally lose its assignments here.
func (st *permissionGroupStore) DeleteCustomRole(ctx context.Context, groupID string, role iam.Role) error {
	var exists bool
	if err := st.q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM group_custom_roles WHERE permission_group_id=$1::uuid AND role=$2)`, groupID, role).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return nil
	}
	for _, table := range []string{"group_user_roles", "group_remote_application_roles", "api_keys", "group_invite_links", "account_registration_invites", "group_custom_roles"} {
		if _, err := st.q.Exec(ctx, "DELETE FROM "+table+" WHERE permission_group_id=$1::uuid AND role=$2", groupID, role); err != nil {
			return err
		}
	}
	st.touched = append(st.touched, authorityTouch{groupID: groupID})
	return nil
}

// SearchGroupInstances searches canonical names only. Former names are addresses,
// not additional directory entries. Keyset ordering keeps the host's paginated
// binding join bounded without loading every group or performing per-row reads.
func (st *permissionGroupStore) SearchGroupInstances(ctx context.Context, persona iam.Persona, query, afterSlug, afterID string, limit int) ([]iam.GroupInstance, error) {
	persona = iam.Persona(strings.TrimSpace(string(persona)))
	query = strings.ToLower(strings.TrimSpace(query))
	afterSlug = strings.ToLower(strings.TrimSpace(afterSlug))
	afterID = strings.TrimSpace(afterID)
	if persona == "" {
		return nil, fmt.Errorf("group search requires a persona")
	}
	if (afterSlug == "") != (afterID == "") {
		return nil, fmt.Errorf("group search cursor requires both slug and id")
	}
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 200 {
		return nil, fmt.Errorf("group search limit must be between 1 and 200")
	}
	rows, err := st.q.Query(ctx, `SELECT id::text,persona,instance_slug,COALESCE(display_name,'')
 FROM permission_groups WHERE persona=$1 AND instance_slug IS NOT NULL AND deleted_at IS NULL
 AND strpos(instance_slug,$2)>0
 AND ($3='' OR (instance_slug,id)>($3,NULLIF($4,'')::uuid))
 ORDER BY instance_slug,id LIMIT $5`, persona, query, afterSlug, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]iam.GroupInstance, 0)
	for rows.Next() {
		var g iam.GroupInstance
		if err := rows.Scan(&g.ID, &g.Persona, &g.InstanceSlug, &g.DisplayName); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
