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
	"time"

	"github.com/open-rails/authkit/iam"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
	// reconcile marks the boot sweep: it retires what it must and logs,
	// never refuses, so no stored state can keep AuthKit from starting.
	reconcile bool
	// actor makes this transaction's changes (zero: AuthKit itself); emit
	// records their events in it. Only Engine.groupStoreFor sets emit.
	actor iam.Actor
	emit  func(context.Context, iam.Actor, ...iam.Event) error
}

// record records events of the store's actor in its transaction.
func (st *permissionGroupStore) record(ctx context.Context, events ...iam.Event) error {
	if len(events) == 0 {
		return nil
	}
	if st.emit == nil {
		return errors.New("authkit: this group store cannot record events")
	}
	return st.emit(ctx, st.actor, events...)
}

// authorityTouch names a group whose grants changed, and the user whose
// authority changed ("" = every holder of an edited role).
type authorityTouch struct{ groupID, userID string }

func (st *permissionGroupStore) touch(groupID string, subject iam.Subject) {
	if subject.Kind != iam.SubjectKindUser {
		return
	}
	id := subject.ID
	if canonical, ok := canonicalUUID(id); ok {
		id = canonical
	}
	st.touched = append(st.touched, authorityTouch{groupID, id})
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
	return id, st.record(ctx, groupEvent(iam.EventGroupCreated, id, g.Persona()))
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
func (st *permissionGroupStore) lockGroup(ctx context.Context, groupID string) (iam.Persona, error) {
	var persona iam.Persona
	err := st.q.QueryRow(ctx, `SELECT persona FROM permission_groups WHERE id=$1::uuid FOR UPDATE`, groupID).Scan(&persona)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", iam.ErrGroupNotFound
	}
	if err != nil {
		return "", err
	}
	if persona == iam.RootPersona {
		return "", fmt.Errorf("the root group cannot be deleted: %w", iam.ErrUnknownGroupPersona)
	}
	return persona, nil
}

func (st *permissionGroupStore) DeleteGroup(ctx context.Context, groupID string, opts iam.PurgeGroupOptions) error {
	persona, err := st.lockGroup(ctx, groupID)
	if err != nil {
		return err
	}
	if !opts.ReleaseSlug {
		if _, err := st.q.Exec(ctx, `UPDATE name_claims SET canonical=false,expires_at=NULL WHERE owner_kind='group' AND owner_id=$1::uuid AND canonical`, groupID); err != nil {
			return err
		}
	}
	if _, err := st.q.Exec(ctx, `DELETE FROM permission_groups WHERE id=$1::uuid`, groupID); err != nil {
		return err
	}
	return st.record(ctx, groupEvent(iam.EventGroupPurged, groupID, persona))
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
// Assigning the role already held changes nothing.
func (st *permissionGroupStore) AssignRole(ctx context.Context, groupID string, subject iam.Subject, role iam.Role) error {
	if subject.Kind == iam.SubjectKindRemoteApplication && role == iam.OwnerRole {
		var operable bool
		if err := st.q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM remote_applications WHERE id=$1::uuid AND enabled AND permission_group_id=$2::uuid)`, subject.ID, groupID).Scan(&operable); err != nil {
			return err
		}
		if !operable {
			return iam.ErrInsufficientAuthority
		}
	}
	table, subjectColumn, err := groupRoleTable(subject.Kind)
	if err != nil {
		return err
	}
	var persona iam.Persona
	err = st.q.QueryRow(ctx, `SELECT persona FROM permission_groups WHERE id=$1::uuid AND deleted_at IS NULL FOR UPDATE`, groupID).Scan(&persona)
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.ErrGroupNotFound
	}
	if err != nil {
		return err
	}
	previous, err := st.directRole(ctx, groupID, subject)
	if err != nil || previous == role {
		return err
	}
	if _, err := st.q.Exec(ctx, fmt.Sprintf(`INSERT INTO %s (permission_group_id, %s, role) VALUES ($1::uuid, $2::uuid, $3)
 ON CONFLICT (permission_group_id, %s) DO UPDATE SET role=EXCLUDED.role`, table, subjectColumn, subjectColumn), groupID, subject.ID, role); err != nil {
		return err
	}
	st.touch(groupID, subject)
	return st.record(ctx, roleEvent(groupID, persona, subject, previous, role))
}

// UnassignRole deletes the matching current assignment.
func (st *permissionGroupStore) UnassignRole(ctx context.Context, groupID string, subject iam.Subject, role iam.Role) error {
	return st.unassign(ctx, groupID, subject, "AND r.role=$3", role)
}

// UnassignSubject deletes the subject's current assignment in this group.
func (st *permissionGroupStore) UnassignSubject(ctx context.Context, groupID string, subject iam.Subject) error {
	return st.unassign(ctx, groupID, subject, "")
}

func (st *permissionGroupStore) unassign(ctx context.Context, groupID string, subject iam.Subject, filter string, args ...any) error {
	table, subjectColumn, err := groupRoleTable(subject.Kind)
	if err != nil {
		return err
	}
	var persona iam.Persona
	var role iam.Role
	err = st.q.QueryRow(ctx, fmt.Sprintf(`DELETE FROM %s r USING permission_groups g
 WHERE g.id=r.permission_group_id AND r.permission_group_id=$1::uuid AND r.%s=$2::uuid %s RETURNING g.persona, r.role`, table, subjectColumn, filter),
		append([]any{groupID, subject.ID}, args...)...).Scan(&persona, &role)
	st.touch(groupID, subject)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return st.record(ctx, roleEvent(groupID, persona, subject, role, ""))
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

// UpsertCustomRole defines or redefines a group's custom role. The caller
// validates the grants and authorizes the change.
func (st *permissionGroupStore) UpsertCustomRole(ctx context.Context, groupID string, role iam.Role, grants []string) error {
	tag, err := st.q.Exec(ctx, `WITH locked AS MATERIALIZED (SELECT id FROM permission_groups WHERE id=$1::uuid AND deleted_at IS NULL FOR UPDATE)
 INSERT INTO group_custom_roles(permission_group_id,role,permissions)
 SELECT id,$2,$3 FROM locked
 ON CONFLICT(permission_group_id,role) DO UPDATE SET permissions=EXCLUDED.permissions,updated_at=now()`, groupID, role, grants)
	if err == nil && tag.RowsAffected() == 0 {
		return iam.ErrGroupNotFound
	}
	if err == nil {
		st.touched = append(st.touched, authorityTouch{groupID: groupID})
	}
	return err
}

// CustomRole returns a group's custom role grants; exists is false when the
// group defines no such role.
func (st *permissionGroupStore) CustomRole(ctx context.Context, groupID string, role iam.Role) (grants []string, exists bool, err error) {
	err = st.q.QueryRow(ctx, `SELECT permissions FROM group_custom_roles WHERE permission_group_id=$1::uuid AND role=$2`, groupID, role).Scan(&grants)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	return grants, err == nil, err
}

// roleRefs counts the live rows in a group that carry one role name.
type roleRefs struct{ users, applications, apiKeys, invites int }

func (r roleRefs) any() bool { return r.users+r.applications+r.apiKeys+r.invites > 0 }

func (st *permissionGroupStore) roleReferences(ctx context.Context, groupID string, role iam.Role) (roleRefs, error) {
	var r roleRefs
	err := st.q.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM group_user_roles WHERE permission_group_id=$1::uuid AND role=$2),
 (SELECT count(*) FROM group_remote_application_roles WHERE permission_group_id=$1::uuid AND role=$2),
 (SELECT count(*) FROM api_keys WHERE permission_group_id=$1::uuid AND role=$2 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now())),
 (SELECT count(*) FROM group_invite_links WHERE permission_group_id=$1::uuid AND role=$2 AND revoked_at IS NULL AND redeemed_at IS NULL AND (expires_at IS NULL OR expires_at>now()))
 + (SELECT count(*) FROM account_registration_invites WHERE permission_group_id=$1::uuid AND role=$2 AND revoked_at IS NULL AND consumed_at IS NULL AND expires_at>now())`,
		groupID, role).Scan(&r.users, &r.applications, &r.apiKeys, &r.invites)
	return r, err
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

// groupsByID reads many groups by id, soft-deleted ones included, in one
// query. Unknown and malformed ids are absent.
func (st *permissionGroupStore) groupsByID(ctx context.Context, groupIDs []string) (map[string]iam.Group, error) {
	out := map[string]iam.Group{}
	ids := groupBatchIDs(groupIDs)
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := st.q.Query(ctx, `SELECT `+groupColumns+` FROM permission_groups WHERE id=ANY($1::uuid[])`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out[g.ID] = g
	}
	return out, rows.Err()
}

// groupByID is groupsByID for one id; absence is ErrGroupNotFound.
func (st *permissionGroupStore) groupByID(ctx context.Context, groupID string) (iam.Group, error) {
	groups, err := st.groupsByID(ctx, []string{groupID})
	if err != nil {
		return iam.Group{}, err
	}
	g, ok := groups[groupID]
	if !ok {
		return iam.Group{}, iam.ErrGroupNotFound
	}
	return g, nil
}

const groupColumns = `id::text, persona, COALESCE(instance_slug,''), COALESCE(display_name,''), deleted_at`

func scanGroup(row pgx.Row) (iam.Group, error) {
	var g iam.Group
	err := row.Scan(&g.ID, &g.Persona, &g.Slug, &g.DisplayName, &g.DeletedAt)
	return g, err
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
	var revoked []iam.Event
	for _, kind := range []iam.SubjectKind{iam.SubjectKindUser, iam.SubjectKindRemoteApplication} {
		table, column, err := groupRoleTable(kind)
		if err != nil {
			return err
		}
		rows, err := st.q.Query(ctx, fmt.Sprintf(`DELETE FROM %s r USING permission_groups g
 WHERE g.id=r.permission_group_id AND r.permission_group_id=$1::uuid AND r.role=$2 RETURNING r.%s::text, g.persona`, table, column), groupID, role)
		if err != nil {
			return err
		}
		events, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (iam.Event, error) {
			var id string
			var persona iam.Persona
			if err := row.Scan(&id, &persona); err != nil {
				return iam.Event{}, err
			}
			return roleEvent(groupID, persona, iam.Subject{Kind: kind, ID: id}, role, ""), nil
		})
		if err != nil {
			return err
		}
		revoked = append(revoked, events...)
	}
	for _, table := range []string{"api_keys", "group_invite_links", "account_registration_invites", "group_custom_roles"} {
		if _, err := st.q.Exec(ctx, "DELETE FROM "+table+" WHERE permission_group_id=$1::uuid AND role=$2", groupID, role); err != nil {
			return err
		}
	}
	st.touched = append(st.touched, authorityTouch{groupID: groupID})
	return st.record(ctx, revoked...)
}
