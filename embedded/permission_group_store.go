package embedded

// DB-backed engine for the permission-group model (#111): the store loads a
// target group's parent chain + the subject's assignments and feeds the tested
// pure decision core (GroupSchema.Can). Hand-written over db.DBTX (pool or tx)
// so it composes with the Client's schema-rewriting wrapper exactly like the
// generated queries; tables are referenced under the historical "profiles."
// schema (rewritten at execution time for custom-schema hosts, authkit #69).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	authkit "github.com/open-rails/authkit"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/internal/db"
)

// SubjectKindUser / SubjectKindRemoteApplication select the concrete group-role
// table used for a principal.
const (
	SubjectKindUser      = authkit.SubjectKindUser
	SubjectKindRemoteApp = authkit.SubjectKindRemoteApp
)

func groupRoleTable(kind authkit.SubjectKind) (table, subjectColumn string, err error) {
	switch kind {
	case SubjectKindUser:
		return "profiles.group_user_roles", "user_id", nil
	case SubjectKindRemoteApp:
		return "profiles.group_remote_application_roles", "remote_application_id", nil
	default:
		return "", "", fmt.Errorf("invalid group subject kind %q", kind)
	}
}

// ErrGroupNotFound is returned when a (persona, instance_slug) or id resolves to no
// live permission-group.
var ErrGroupNotFound = authkit.ErrGroupNotFound

// ErrGroupSlugTaken: the requested instance slug is held live by another group
// or reserved to one until the deadline recorded when its owner renamed.
var ErrGroupSlugTaken = authkit.ErrGroupSlugTaken

// ErrGroupSlugApplicationManaged: the group's slug mirrors a domain-rooted
// application's slug (= its proven domain); it renames only through the
// application repoint flow, never directly.
var ErrGroupSlugApplicationManaged = authkit.ErrGroupSlugApplicationManaged

// PermissionGroupStore is the database access layer for permission-groups. It
// holds a db.DBTX (a *pgxpool.Pool or a pgx.Tx), so callers choose the txn scope.
type PermissionGroupStore struct {
	q   db.DBTX
	now func() time.Time
}

// NewPermissionGroupStore wraps a db.DBTX (pool or transaction).
func NewPermissionGroupStore(q db.DBTX) *PermissionGroupStore {
	return &PermissionGroupStore{q: q, now: time.Now}
}

// SeedContainment reconciles the containment schema (group_persona_parents) from a
// validated GroupSchema. Idempotent; call once at bootstrap so the DB trigger
// can enforce the declared tree shape. root has no rows (parentless).
func (st *PermissionGroupStore) SeedContainment(ctx context.Context, schema *GroupSchema) error {
	live := make([]string, 0, len(schema.Personas()))
	for _, persona := range schema.Personas() {
		if schema.IsRoot(persona) {
			continue
		}
		td, _ := schema.Persona(persona)
		parent := td.Parent
		if _, err := st.q.Exec(ctx,
			`INSERT INTO profiles.group_persona_parents (persona, parent_persona)
			 VALUES ($1, $2)
			 ON CONFLICT (persona) DO UPDATE SET parent_persona = EXCLUDED.parent_persona`,
			persona, parent); err != nil {
			return fmt.Errorf("seed containment %s<-%s: %w", persona, parent, err)
		}
		live = append(live, string(persona))
	}
	if len(live) == 0 {
		_, err := st.q.Exec(ctx, `DELETE FROM profiles.group_persona_parents`)
		return err
	}
	_, err := st.q.Exec(ctx, `DELETE FROM profiles.group_persona_parents WHERE NOT (persona = ANY($1))`, live)
	return err
}

// CreateGroup inserts a permission-group and returns its internal id. parentID
// is empty for the root group. The containment trigger + CHECK enforce shape at
// the DB (the trigger resolves the parent's persona by parent_id); callers
// SHOULD also pre-validate via GroupSchema.ValidateParent for a clear error
// before hitting the DB.
func (st *PermissionGroupStore) CreateGroup(ctx context.Context, g authkit.GroupRef, parentID string) (string, error) {
	return st.CreateGroupNamed(ctx, g, parentID, "")
}

// CreateGroupNamed is CreateGroup with a first-class display name (#264):
// free-form, non-unique vanity metadata (the slug stays the unique handle).
func (st *PermissionGroupStore) CreateGroupNamed(ctx context.Context, g authkit.GroupRef, parentID, displayName string) (string, error) {
	var id string
	err := st.q.QueryRow(ctx,
		`WITH identity AS MATERIALIZED (SELECT uuidv7() AS id),
         claim AS MATERIALIZED (SELECT id, profiles.claim_canonical_name('group',$1,$3,id,$5) FROM identity)
         INSERT INTO profiles.permission_groups (id,persona,parent_id,instance_slug,display_name)
         SELECT id,$1,NULLIF($2,'')::uuid,NULLIF($3,''),$4 FROM claim RETURNING id::text`,
		g.Persona, parentID, g.Instance, displayName, st.now()).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create %q group: %w", g.Persona, nameClaimError(err, "group"))
	}
	return id, nil
}

// SetGroupDisplayName updates a group's free-form display name.
func (st *PermissionGroupStore) SetGroupDisplayName(ctx context.Context, groupID, displayName string) error {
	_, err := st.q.Exec(ctx,
		`UPDATE profiles.permission_groups SET display_name = $2 WHERE id = $1::uuid`,
		groupID, displayName)
	return err
}

// DeleteGroup deletes the whole subtree in the caller's transaction. It reserves
// every final canonical name unless explicitly released; prior aliases keep
// their existing deadlines. Parent locks block new FK children while each next
// level is read from a fresh statement snapshot and locked against renames.
func (st *PermissionGroupStore) DeleteGroup(ctx context.Context, groupID string, opts authkit.DeletePermissionGroupOptions) error {
	var persona authkit.Persona
	err := st.q.QueryRow(ctx, `SELECT persona FROM profiles.permission_groups WHERE id=$1::uuid FOR UPDATE`, groupID).Scan(&persona)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrGroupNotFound
	}
	if err != nil {
		return err
	}
	if persona == RootPersona {
		return fmt.Errorf("the root group cannot be deleted: %w", authkit.ErrUnknownGroupPersona)
	}
	ids, frontier := []string{groupID}, []string{groupID}
	seen := map[string]bool{groupID: true}
	for len(frontier) > 0 {
		rows, err := st.q.Query(ctx, `SELECT id::text FROM profiles.permission_groups WHERE parent_id=ANY($1::uuid[]) ORDER BY id FOR UPDATE`, frontier)
		if err != nil {
			return err
		}
		var next []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
				next = append(next, id)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		frontier = next
	}
	if !opts.ReleaseSlug {
		if _, err := st.q.Exec(ctx, `UPDATE profiles.name_claims SET canonical=false,expires_at=NULL WHERE owner_kind='group' AND owner_id=ANY($1::uuid[]) AND canonical`, ids); err != nil {
			return err
		}
	}
	_, err = st.q.Exec(ctx, `DELETE FROM profiles.permission_groups WHERE id=$1::uuid`, groupID)
	return err
}

// InstanceSlugAvailable applies exactly the resolver's request-time expiry rule.
func (st *PermissionGroupStore) InstanceSlugAvailable(ctx context.Context, g authkit.GroupRef) (bool, error) {
	var available bool
	err := st.q.QueryRow(ctx, `SELECT NOT EXISTS (SELECT 1 FROM profiles.name_claims WHERE owner_kind='group' AND persona=$1 AND name=lower($2) AND (canonical OR expires_at IS NULL OR expires_at>$3))`, g.Persona, g.Instance, st.now()).Scan(&available)
	return available, err
}

// RenameGroupSlug requires the group owner row locked in the caller transaction.
// It reads the outgoing spelling again rather than trusting a route's old alias.
func (st *PermissionGroupStore) renameGroupSlug(ctx context.Context, groupID, newSlug string, policy authkit.NamingPolicy) error {
	var persona string
	var old *string
	var last *time.Time
	err := st.q.QueryRow(ctx, `SELECT persona,instance_slug,last_renamed_at FROM profiles.permission_groups WHERE id=$1::uuid FOR UPDATE`, groupID).Scan(&persona, &old, &last)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrGroupNotFound
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
	_, err = st.q.Exec(ctx, `UPDATE profiles.permission_groups SET instance_slug=$2,last_renamed_at=$3 WHERE id=$1::uuid`, groupID, newSlug, now)
	return err
}

func (st *PermissionGroupStore) ResolveGroupSlug(ctx context.Context, g authkit.GroupRef) (authkit.NameResolution, error) {
	var out authkit.NameResolution
	err := st.q.QueryRow(ctx, `SELECT g.id::text,g.instance_slug,NOT c.canonical,c.expires_at FROM profiles.name_claims c JOIN profiles.permission_groups g ON g.id=c.owner_id WHERE c.owner_kind='group' AND c.persona=$1 AND c.name=lower($2) AND (c.canonical OR c.expires_at IS NULL OR c.expires_at>$3)`, g.Persona, g.Instance, st.now()).Scan(&out.ID, &out.CanonicalName, &out.IsAlias, &out.AliasExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrGroupNotFound
	}
	return out, err
}

func (st *PermissionGroupStore) GroupByInstanceSlug(ctx context.Context, g authkit.GroupRef) (string, error) {
	if id, bound, err := st.requestGroupID(ctx, g); bound {
		return id, err
	}
	out, err := st.ResolveGroupSlug(ctx, g)
	return out.ID, err
}

// GroupByLiveInstanceSlug resolves (persona, instance_slug) WITHOUT tombstone
// forwarding — the group currently holding the slug, or ErrGroupNotFound.
func (st *PermissionGroupStore) GroupByLiveInstanceSlug(ctx context.Context, g authkit.GroupRef) (string, error) {
	var id string
	err := st.q.QueryRow(ctx,
		`SELECT id::text FROM profiles.permission_groups
		 WHERE persona = $1 AND instance_slug = $2`,
		g.Persona, g.Instance).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrGroupNotFound
	}
	if err != nil {
		return "", err
	}
	return id, nil
}

// RootGroupID returns the singleton root group's internal id (ErrGroupNotFound
// if the deployment has not seeded one yet).
func (st *PermissionGroupStore) RootGroupID(ctx context.Context) (string, error) {
	var id string
	err := st.q.QueryRow(ctx,
		`SELECT id::text FROM profiles.permission_groups WHERE persona = 'root'`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrGroupNotFound
	}
	return id, err
}

// WalkAssignments walks the target group's parent chain to the root and returns
// the subject's assignments at each ancestor where it holds at least one role —
// exactly the []GroupAssignment that GroupSchema.ResolveGrants/Can consume. This
// is the additive walk-up made concrete.
func (st *PermissionGroupStore) WalkAssignments(ctx context.Context, groupID string, subject authkit.Subject) ([]GroupAssignment, error) {
	assignments, _, err := st.assignmentsWithCustomRoles(ctx, groupID, subject, false)
	return assignments, err
}

// Memberships and their mutable custom definitions come from one MVCC snapshot.
// A delete/recreate cannot combine a retired membership with the replacement
// role's permissions. Include all definitions on assigned groups, preserving
// the existing authorization resolver's scope for target-role checks.
func (st *PermissionGroupStore) assignmentsWithCustomRoles(ctx context.Context, groupID string, subject authkit.Subject, definitions bool) ([]GroupAssignment, CustomRoleResolver, error) {
	table, column, err := groupRoleTable(subject.Kind)
	if err != nil {
		return nil, nil, err
	}
	rows, err := st.q.Query(ctx, fmt.Sprintf(`WITH RECURSIVE chain AS (
 SELECT id,persona,parent_id FROM profiles.permission_groups WHERE id=$1::uuid
 UNION ALL SELECT p.id,p.persona,p.parent_id FROM profiles.permission_groups p JOIN chain c ON p.id=c.parent_id)
 SELECT c.id::text,c.persona,a.role,r.role,r.permissions FROM chain c
 JOIN %s a ON a.permission_group_id=c.id AND a.%s=$2::uuid
 LEFT JOIN profiles.group_custom_roles r ON r.permission_group_id=c.id AND $3
 ORDER BY c.id,r.role`, table, column), groupID, subject.ID, definitions)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	type key struct {
		group string
		role  authkit.Role
	}
	custom := map[key][]string{}
	seen := map[string]bool{}
	var assignments []GroupAssignment
	for rows.Next() {
		var assignment GroupAssignment
		var role *string
		var permissions []string
		if err := rows.Scan(&assignment.PermissionGroupID, &assignment.Persona, &assignment.Role, &role, &permissions); err != nil {
			return nil, nil, err
		}
		if !seen[assignment.PermissionGroupID] {
			seen[assignment.PermissionGroupID] = true
			assignments = append(assignments, assignment)
		}
		if role != nil {
			custom[key{assignment.PermissionGroupID, authkit.Role(*role)}] = permissions
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return assignments, func(group string, role authkit.Role) ([]string, bool) {
		p, ok := custom[key{group, role}]
		return p, ok
	}, nil
}

// RootRolesForUsers returns, for each user id, the role slugs directly assigned on
// the root group (rootGID). Root roles are direct assignments on the parentless
// root group, so no parent walk is needed — this batches a whole page's lookups
// into one query (the admin-directory enrichment path; avoids a per-row N+1).
func (st *PermissionGroupStore) RootRolesForUsers(ctx context.Context, rootGID string, userIDs []string) (map[string][]string, error) {
	out := make(map[string][]string, len(userIDs))
	if len(userIDs) == 0 {
		return out, nil
	}
	rows, err := st.q.Query(ctx,
		`SELECT user_id::text, role FROM profiles.group_user_roles
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
func (st *PermissionGroupStore) AssignRole(ctx context.Context, groupID string, subject authkit.Subject, role authkit.Role) error {
	table, subjectColumn, err := groupRoleTable(subject.Kind)
	if err != nil {
		return err
	}
	tag, err := st.q.Exec(ctx, fmt.Sprintf(`WITH locked AS MATERIALIZED (SELECT id FROM profiles.permission_groups WHERE id=$1::uuid FOR UPDATE)
 INSERT INTO %s (permission_group_id, %s, role)
 SELECT id, $2::uuid, $3 FROM locked
 ON CONFLICT (permission_group_id, %s)
 DO UPDATE SET role=EXCLUDED.role`, table, subjectColumn, subjectColumn), groupID, subject.ID, role)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrGroupNotFound
	}
	return err
}

// UnassignRole deletes the matching current assignment.
func (st *PermissionGroupStore) UnassignRole(ctx context.Context, groupID string, subject authkit.Subject, role authkit.Role) error {
	table, subjectColumn, err := groupRoleTable(subject.Kind)
	if err != nil {
		return err
	}
	_, err = st.q.Exec(ctx,
		fmt.Sprintf(`DELETE FROM %s
		 WHERE permission_group_id = $1::uuid AND %s = $2::uuid AND role = $3`,
			table, subjectColumn),
		groupID, subject.ID, role)
	return err
}

// UnassignSubject deletes the subject's current assignment in this group.
func (st *PermissionGroupStore) UnassignSubject(ctx context.Context, groupID string, subject authkit.Subject) error {
	table, subjectColumn, err := groupRoleTable(subject.Kind)
	if err != nil {
		return err
	}
	_, err = st.q.Exec(ctx,
		fmt.Sprintf(`DELETE FROM %s
		 WHERE permission_group_id = $1::uuid AND %s = $2::uuid`, table, subjectColumn),
		groupID, subject.ID)
	return err
}

// OwnerCount returns the count of live, unbanned, unreserved user owners and
// enabled application owners. Lifecycle safety uses the transaction-bound
// Client guard, which also checks the deployment's MFA policy.
func (st *PermissionGroupStore) OwnerCount(ctx context.Context, groupID string) (int, error) {
	var n int
	err := st.q.QueryRow(ctx, `SELECT
    (SELECT count(*) FROM profiles.group_user_roles r JOIN profiles.users u ON u.id=r.user_id
     WHERE r.permission_group_id=$1::uuid AND r.role='owner' AND u.deleted_at IS NULL
     AND COALESCE(u.metadata->'reserved','false'::jsonb)<>'true'::jsonb
     AND ((u.banned_at IS NULL AND u.banned_until IS NULL AND u.ban_reason IS NULL AND u.banned_by IS NULL) OR u.banned_until<=statement_timestamp()))
    + (SELECT count(*) FROM profiles.group_remote_application_roles r JOIN profiles.remote_applications a ON a.id=r.remote_application_id
       WHERE r.permission_group_id=$1::uuid AND r.role='owner' AND a.enabled)`, groupID).Scan(&n)
	return n, err
}

// UpsertCustomRole defines/updates a per-group custom role's permission set and
// its requires_mfa flag (#247). Only meaningful for personas whose CustomRoles
// capability is set; the caller enforces that + validates each grant pattern
// against the group's persona.
func (st *PermissionGroupStore) UpsertCustomRole(ctx context.Context, groupID string, def authkit.CustomRoleDef) error {
	tag, err := st.q.Exec(ctx, `WITH locked AS MATERIALIZED (SELECT id FROM profiles.permission_groups WHERE id=$1::uuid FOR UPDATE)
 INSERT INTO profiles.group_custom_roles(permission_group_id,role,permissions,requires_mfa)
 SELECT id,$2,$3,$4 FROM locked
 ON CONFLICT(permission_group_id,role) DO UPDATE SET permissions=EXCLUDED.permissions,requires_mfa=EXCLUDED.requires_mfa,updated_at=now()`, groupID, def.Role, def.Permissions, def.RequiresMFA)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrGroupNotFound
	}
	return err
}

// CustomRole returns a single per-group custom role's stored permissions and
// requires_mfa flag, or (nil, false, nil) if no such custom role is defined —
// absence is not an error (the caller may be about to CREATE it).
func (st *PermissionGroupStore) CustomRole(ctx context.Context, groupID string, role authkit.Role) (permissions []string, requiresMFA bool, err error) {
	err = st.q.QueryRow(ctx,
		`SELECT permissions, requires_mfa FROM profiles.group_custom_roles
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
func (st *PermissionGroupStore) CustomRolesFor(ctx context.Context, groupIDs []string) (CustomRoleResolver, error) {
	if len(groupIDs) == 0 {
		return func(string, authkit.Role) ([]string, bool) { return nil, false }, nil
	}
	rows, err := st.q.Query(ctx,
		`SELECT permission_group_id::text, role, permissions FROM profiles.group_custom_roles
		 WHERE permission_group_id = ANY($1::uuid[])`,
		groupIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type key struct {
		g string
		r authkit.Role
	}
	m := map[key][]string{}
	for rows.Next() {
		var gid string
		var role authkit.Role
		var perms []string
		if err := rows.Scan(&gid, &role, &perms); err != nil {
			return nil, err
		}
		m[key{gid, role}] = perms
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return func(groupID string, role authkit.Role) ([]string, bool) {
		p, ok := m[key{groupID, role}]
		return p, ok
	}, nil
}

// CanOnGroup is the end-to-end DB-backed authorization check: walk the target
// group's chain, preload any custom roles, and test perm coverage against the
// schema. The caller constructs perm per the two-persona rule (e.g. for an
// action on a persona-RT resource reached from an ancestor of persona LT, the perm is
// `LT:RT:<action>`).
func (st *PermissionGroupStore) CanOnGroup(ctx context.Context, schema *GroupSchema, subject authkit.Subject, groupID string, perm authkit.Perm) (bool, error) {
	assignments, resolver, err := st.assignmentsWithCustomRoles(ctx, groupID, subject, true)
	if err != nil {
		return false, err
	}
	return schema.Can(assignments, resolver, perm), nil
}

// GrantsOnGroup returns the de-duplicated UNION of grant PATTERNS the subject
// holds in the group addressed by groupID (its assignments across the parent
// chain), resolved against the schema's catalog + per-group custom roles. Unlike
// CanOnGroup (which tests ONE perm), this returns the whole effective grant set
// as PATTERNS — globs like `root:*` are returned verbatim, NOT expanded into every
// concrete perm (the caller glob-matches with authkit.Perm.Matches). Powers the
// permission-introspection endpoint (authkit/doujins #421). An empty assignment
// set returns an empty (non-nil) slice.
func (st *PermissionGroupStore) GrantsOnGroup(ctx context.Context, schema *GroupSchema, subject authkit.Subject, groupID string) ([]string, error) {
	assignments, resolver, err := st.assignmentsWithCustomRoles(ctx, groupID, subject, true)
	if err != nil {
		return nil, err
	}
	grants := schema.ResolveGrants(assignments, resolver)
	if grants == nil {
		grants = []string{}
	}
	return grants, nil
}

// GroupMember is one role-assignment in a group (roster listing).
type GroupMember = authkit.GroupMember

// GroupMembers lists the live role-assignments in a group.
func (st *PermissionGroupStore) GroupMembers(ctx context.Context, groupID string) ([]GroupMember, error) {
	rows, err := st.q.Query(ctx,
		`SELECT user_id::text, 'user' AS subject_kind, role FROM profiles.group_user_roles
		 WHERE permission_group_id = $1::uuid
		 UNION ALL
		 SELECT remote_application_id::text, 'remote_application' AS subject_kind, role
		   FROM profiles.group_remote_application_roles
		  WHERE permission_group_id = $1::uuid
		 ORDER BY 1, 3`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupMember
	for rows.Next() {
		var m GroupMember
		if err := rows.Scan(&m.SubjectID, &m.SubjectKind, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// SubjectGroupMembership is one (persona, resource, role) a subject holds.
type SubjectGroupMembership = authkit.SubjectGroupMembership

// GroupInstance is a persona instance's own identity (#269).
type GroupInstance = authkit.GroupInstance

// SubjectGroups lists every group membership a subject holds (cross-persona),
// the data behind /me/groups.
func (st *PermissionGroupStore) SubjectGroups(ctx context.Context, subject authkit.Subject) ([]SubjectGroupMembership, error) {
	table, subjectColumn, err := groupRoleTable(subject.Kind)
	if err != nil {
		return nil, err
	}
	rows, err := st.q.Query(ctx,
		fmt.Sprintf(`SELECT g.id::text, g.persona, COALESCE(g.instance_slug, ''), g.display_name, a.role
		 FROM %s a
		 JOIN profiles.permission_groups g ON g.id = a.permission_group_id
		 WHERE a.%s = $1::uuid
		 ORDER BY g.persona, g.instance_slug, a.role`, table, subjectColumn), subject.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SubjectGroupMembership
	for rows.Next() {
		var m SubjectGroupMembership
		if err := rows.Scan(&m.GroupID, &m.Persona, &m.InstanceSlug, &m.DisplayName, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// GroupInstanceByID reads one group's own identity row (#269) — the descriptor
// behind GET /<persona>/:instance_slug and the `group_id` on the creation
// response. Takes an id the caller already resolved from (persona, slug), so
// tombstone forwarding and the root singleton are handled once, upstream.
func (st *PermissionGroupStore) GroupInstanceByID(ctx context.Context, groupID string) (GroupInstance, error) {
	var g GroupInstance
	err := st.q.QueryRow(ctx,
		`SELECT id::text, persona, COALESCE(instance_slug, ''), COALESCE(display_name, '')
		   FROM profiles.permission_groups WHERE id = $1::uuid`,
		groupID).Scan(&g.ID, &g.Persona, &g.InstanceSlug, &g.DisplayName)
	if errors.Is(err, pgx.ErrNoRows) {
		return GroupInstance{}, ErrGroupNotFound
	}
	if err != nil {
		return GroupInstance{}, err
	}
	return g, nil
}

// DeleteCustomRole retires a definition and every reference to it. The caller
// must hold the group lifecycle lock in a transaction. An absent definition is
// a no-op, so a catalog role cannot accidentally lose its assignments here.
func (st *PermissionGroupStore) DeleteCustomRole(ctx context.Context, groupID string, role authkit.Role) error {
	var exists bool
	if err := st.q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM profiles.group_custom_roles WHERE permission_group_id=$1::uuid AND role=$2)`, groupID, role).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return nil
	}
	for _, table := range []string{"group_user_roles", "group_remote_application_roles", "api_keys", "group_invite_links", "account_registration_invites", "group_custom_roles"} {
		if _, err := st.q.Exec(ctx, "DELETE FROM profiles."+table+" WHERE permission_group_id=$1::uuid AND role=$2", groupID, role); err != nil {
			return err
		}
	}
	return nil
}

// SearchGroupInstances searches canonical names only. Former names are addresses,
// not additional directory entries. Keyset ordering keeps the host's paginated
// binding join bounded without loading every group or performing per-row reads.
func (st *PermissionGroupStore) SearchGroupInstances(ctx context.Context, persona authkit.Persona, query, afterSlug, afterID string, limit int) ([]GroupInstance, error) {
	persona = authkit.Persona(strings.TrimSpace(string(persona)))
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
 FROM profiles.permission_groups WHERE persona=$1 AND instance_slug IS NOT NULL
 AND strpos(instance_slug,$2)>0
 AND ($3='' OR (instance_slug,id)>($3,NULLIF($4,'')::uuid))
 ORDER BY instance_slug,id LIMIT $5`, persona, query, afterSlug, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]GroupInstance, 0)
	for rows.Next() {
		var g GroupInstance
		if err := rows.Scan(&g.ID, &g.Persona, &g.InstanceSlug, &g.DisplayName); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
