package authcore

// DB-backed engine for the permission-group model (#111): the store loads a
// target group's parent chain + the subject's assignments and feeds the tested
// pure decision core (GroupSchema.Can). Hand-written over db.DBTX (pool or tx)
// so it composes with the Service's schema-rewriting wrapper exactly like the
// generated queries; tables are referenced under the historical "profiles."
// schema (rewritten at execution time for custom-schema hosts, authkit #69).

import (
	"context"
	"errors"
	"fmt"
	authkit "github.com/open-rails/authkit"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/internal/db"
)

// SubjectKindUser / SubjectKindRemoteApplication select the concrete group-role
// table used for a principal.
const (
	SubjectKindUser      = "user"
	SubjectKindRemoteApp = "remote_application"
)

func groupRoleTable(subjectKind string) (table, subjectColumn string, err error) {
	switch subjectKind {
	case SubjectKindUser:
		return "profiles.group_user_roles", "user_id", nil
	case SubjectKindRemoteApp:
		return "profiles.group_remote_application_roles", "remote_application_id", nil
	default:
		return "", "", fmt.Errorf("invalid group subject kind %q", subjectKind)
	}
}

// ErrGroupNotFound is returned when a (persona, instance_slug) or id resolves to no
// live permission-group.
var ErrGroupNotFound = authkit.ErrGroupNotFound

// PermissionGroupStore is the database access layer for permission-groups. It
// holds a db.DBTX (a *pgxpool.Pool or a pgx.Tx), so callers choose the txn scope.
type PermissionGroupStore struct {
	q db.DBTX
}

// NewPermissionGroupStore wraps a db.DBTX (pool or transaction).
func NewPermissionGroupStore(q db.DBTX) *PermissionGroupStore {
	return &PermissionGroupStore{q: q}
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
		live = append(live, persona)
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
func (st *PermissionGroupStore) CreateGroup(ctx context.Context, persona, parentID, instanceSlug string) (string, error) {
	var id string
	err := st.q.QueryRow(ctx,
		`INSERT INTO profiles.permission_groups (persona, parent_id, instance_slug)
		 VALUES ($1, NULLIF($2,'')::uuid, NULLIF($3,''))
		 RETURNING id::text`,
		persona, parentID, instanceSlug).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create %q group: %w", persona, err)
	}
	return id, nil
}

// GroupByInstanceSlug resolves a group by its API addressing key (persona,
// instance_slug) — the route layer's (persona, instance_slug). Returns the internal
// id, which never leaves authkit.
func (st *PermissionGroupStore) GroupByInstanceSlug(ctx context.Context, persona, instanceSlug string) (string, error) {
	var id string
	err := st.q.QueryRow(ctx,
		`SELECT id::text FROM profiles.permission_groups
		 WHERE persona = $1 AND instance_slug = $2`,
		persona, instanceSlug).Scan(&id)
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
func (st *PermissionGroupStore) WalkAssignments(ctx context.Context, groupID, subjectID, subjectKind string) ([]GroupAssignment, error) {
	table, subjectColumn, err := groupRoleTable(subjectKind)
	if err != nil {
		return nil, err
	}
	rows, err := st.q.Query(ctx,
		fmt.Sprintf(`WITH RECURSIVE chain AS (
			SELECT id, persona, parent_id FROM profiles.permission_groups
			WHERE id = $1::uuid
			UNION ALL
			SELECT p.id, p.persona, p.parent_id FROM profiles.permission_groups p
			JOIN chain c ON p.id = c.parent_id
		)
		SELECT c.id::text, c.persona, a.role
		FROM chain c
		LEFT JOIN %s a
		  ON a.permission_group_id = c.id AND a.%s = $2::uuid AND a.deleted_at IS NULL
		ORDER BY c.id`, table, subjectColumn),
		groupID, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// #247: at most one live role per (group, subject) — enforced by the
	// partial unique index — so the join yields at most one row per group.
	type acc struct {
		typ  string
		role *string
	}
	byGroup := map[string]*acc{}
	var order []string
	for rows.Next() {
		var gid, gtype string
		var role *string
		if err := rows.Scan(&gid, &gtype, &role); err != nil {
			return nil, err
		}
		a, ok := byGroup[gid]
		if !ok {
			a = &acc{typ: gtype}
			byGroup[gid] = a
			order = append(order, gid)
		}
		if role != nil {
			a.role = role
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []GroupAssignment
	for _, gid := range order {
		a := byGroup[gid]
		if a.role == nil {
			continue // an ancestor where the subject holds nothing contributes no grants
		}
		out = append(out, GroupAssignment{Persona: a.typ, PermissionGroupID: gid, Role: *a.role})
	}
	return out, nil
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
		 WHERE permission_group_id = $1::uuid AND user_id = ANY($2::uuid[]) AND deleted_at IS NULL`,
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

// AssignRole grants subject a role in a group, REPLACING any previous role it
// held there (#247 hard rule: one role per subject per group, enforced by a
// partial unique index on (permission_group_id, subject) — no per-group role
// unions). A single atomic UPSERT: no live row yet -> insert fresh; a live row
// already exists (whatever role it holds) -> its role is overwritten in place.
// Deliberately NOT a soft-delete-then-insert (a two-statement version of that
// has a same-snapshot visibility trap: a writable CTE's UPDATE is invisible to
// the following INSERT's ON CONFLICT check in the SAME command, so the INSERT
// would spuriously conflict with the row the CTE just tried to retire and
// silently no-op instead of swapping the role). The role NAME is validated
// against the persona catalog / custom roles by the caller before assignment.
func (st *PermissionGroupStore) AssignRole(ctx context.Context, groupID, subjectID, subjectKind, role string) error {
	table, subjectColumn, err := groupRoleTable(subjectKind)
	if err != nil {
		return err
	}
	_, err = st.q.Exec(ctx,
		fmt.Sprintf(`INSERT INTO %s (permission_group_id, %s, role)
		 VALUES ($1::uuid, $2::uuid, $3)
		 ON CONFLICT (permission_group_id, %s) WHERE deleted_at IS NULL
		 DO UPDATE SET role = EXCLUDED.role, updated_at = now()`, table, subjectColumn, subjectColumn),
		groupID, subjectID, role)
	return err
}

// UnassignRole soft-deletes a role assignment.
func (st *PermissionGroupStore) UnassignRole(ctx context.Context, groupID, subjectID, subjectKind, role string) error {
	table, subjectColumn, err := groupRoleTable(subjectKind)
	if err != nil {
		return err
	}
	_, err = st.q.Exec(ctx,
		fmt.Sprintf(`UPDATE %s SET deleted_at = now(), updated_at = now()
		 WHERE permission_group_id = $1::uuid AND %s = $2::uuid AND role = $3 AND deleted_at IS NULL`,
			table, subjectColumn),
		groupID, subjectID, role)
	return err
}

// UnassignSubject soft-deletes every active role assignment a subject holds in a group.
func (st *PermissionGroupStore) UnassignSubject(ctx context.Context, groupID, subjectID, subjectKind string) error {
	table, subjectColumn, err := groupRoleTable(subjectKind)
	if err != nil {
		return err
	}
	_, err = st.q.Exec(ctx,
		fmt.Sprintf(`UPDATE %s SET deleted_at = now(), updated_at = now()
		 WHERE permission_group_id = $1::uuid AND %s = $2::uuid AND deleted_at IS NULL`, table, subjectColumn),
		groupID, subjectID)
	return err
}

// OwnerCount returns how many subjects (users + remote applications) currently
// hold the owner role in a group — the last-owner guard (#193) refuses to remove
// the final owner so a group can never be orphaned.
func (st *PermissionGroupStore) OwnerCount(ctx context.Context, groupID string) (int, error) {
	var n int
	err := st.q.QueryRow(ctx,
		`SELECT
		   (SELECT count(*) FROM profiles.group_user_roles
		      WHERE permission_group_id = $1::uuid AND role = $2 AND deleted_at IS NULL)
		 + (SELECT count(*) FROM profiles.group_remote_application_roles
		      WHERE permission_group_id = $1::uuid AND role = $2 AND deleted_at IS NULL)`,
		groupID, OwnerRoleName).Scan(&n)
	return n, err
}

// UpsertCustomRole defines/updates a per-group custom role's permission set and
// its requires_mfa flag (#247). Only meaningful for personas whose CustomRoles
// capability is set; the caller enforces that + validates each grant pattern
// against the group's persona.
func (st *PermissionGroupStore) UpsertCustomRole(ctx context.Context, groupID, role string, permissions []string, requiresMFA bool) error {
	_, err := st.q.Exec(ctx,
		`INSERT INTO profiles.group_custom_roles (permission_group_id, role, permissions, requires_mfa)
		 VALUES ($1::uuid, $2, $3, $4)
		 ON CONFLICT (permission_group_id, role)
		 DO UPDATE SET permissions = EXCLUDED.permissions, requires_mfa = EXCLUDED.requires_mfa, updated_at = now()`,
		groupID, role, permissions, requiresMFA)
	return err
}

// CustomRole returns a single per-group custom role's stored permissions and
// requires_mfa flag, or (nil, false, nil) if no such custom role is defined —
// absence is not an error (the caller may be about to CREATE it).
func (st *PermissionGroupStore) CustomRole(ctx context.Context, groupID, role string) (permissions []string, requiresMFA bool, err error) {
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
		return func(string, string) ([]string, bool) { return nil, false }, nil
	}
	rows, err := st.q.Query(ctx,
		`SELECT permission_group_id::text, role, permissions FROM profiles.group_custom_roles
		 WHERE permission_group_id = ANY($1::uuid[])`,
		groupIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type key struct{ g, r string }
	m := map[key][]string{}
	for rows.Next() {
		var gid, role string
		var perms []string
		if err := rows.Scan(&gid, &role, &perms); err != nil {
			return nil, err
		}
		m[key{gid, role}] = perms
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return func(groupID, role string) ([]string, bool) {
		p, ok := m[key{groupID, role}]
		return p, ok
	}, nil
}

// CanOnGroup is the end-to-end DB-backed authorization check: walk the target
// group's chain, preload any custom roles, and test perm coverage against the
// schema. The caller constructs perm per the two-persona rule (e.g. for an
// action on a persona-RT resource reached from an ancestor of persona LT, the perm is
// `LT:RT:<action>`).
func (st *PermissionGroupStore) CanOnGroup(ctx context.Context, schema *GroupSchema, subjectID, subjectKind, groupID, perm string) (bool, error) {
	asg, err := st.WalkAssignments(ctx, groupID, subjectID, subjectKind)
	if err != nil {
		return false, err
	}
	if len(asg) == 0 {
		return false, nil
	}
	ids := make([]string, 0, len(asg))
	for _, a := range asg {
		ids = append(ids, a.PermissionGroupID)
	}
	resolver, err := st.CustomRolesFor(ctx, ids)
	if err != nil {
		return false, err
	}
	return schema.Can(asg, resolver, perm), nil
}

// GrantsOnGroup returns the de-duplicated UNION of grant PATTERNS the subject
// holds in the group addressed by groupID (its assignments across the parent
// chain), resolved against the schema's catalog + per-group custom roles. Unlike
// CanOnGroup (which tests ONE perm), this returns the whole effective grant set
// as PATTERNS — globs like `root:*` are returned verbatim, NOT expanded into every
// concrete perm (the caller glob-matches with authkit.PermMatches). Powers the
// permission-introspection endpoint (authkit/doujins #421). An empty assignment
// set returns an empty (non-nil) slice.
func (st *PermissionGroupStore) GrantsOnGroup(ctx context.Context, schema *GroupSchema, subjectID, subjectKind, groupID string) ([]string, error) {
	asg, err := st.WalkAssignments(ctx, groupID, subjectID, subjectKind)
	if err != nil {
		return nil, err
	}
	if len(asg) == 0 {
		return []string{}, nil
	}
	ids := make([]string, 0, len(asg))
	for _, a := range asg {
		ids = append(ids, a.PermissionGroupID)
	}
	resolver, err := st.CustomRolesFor(ctx, ids)
	if err != nil {
		return nil, err
	}
	grants := schema.ResolveGrants(asg, resolver)
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
		 WHERE permission_group_id = $1::uuid AND deleted_at IS NULL
		 UNION ALL
		 SELECT remote_application_id::text, 'remote_application' AS subject_kind, role
		   FROM profiles.group_remote_application_roles
		  WHERE permission_group_id = $1::uuid AND deleted_at IS NULL
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

// SubjectGroups lists every group membership a subject holds (cross-persona),
// the data behind /me/groups.
func (st *PermissionGroupStore) SubjectGroups(ctx context.Context, subjectID, subjectKind string) ([]SubjectGroupMembership, error) {
	table, subjectColumn, err := groupRoleTable(subjectKind)
	if err != nil {
		return nil, err
	}
	rows, err := st.q.Query(ctx,
		fmt.Sprintf(`SELECT g.persona, COALESCE(g.instance_slug, ''), a.role
		 FROM %s a
		 JOIN profiles.permission_groups g ON g.id = a.permission_group_id
		 WHERE a.%s = $1::uuid AND a.deleted_at IS NULL
		 ORDER BY g.persona, g.instance_slug, a.role`, table, subjectColumn), subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SubjectGroupMembership
	for rows.Next() {
		var m SubjectGroupMembership
		if err := rows.Scan(&m.Persona, &m.InstanceSlug, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeleteCustomRole removes a per-group custom role (and its permissions).
func (st *PermissionGroupStore) DeleteCustomRole(ctx context.Context, groupID, role string) error {
	_, err := st.q.Exec(ctx,
		`DELETE FROM profiles.group_custom_roles WHERE permission_group_id = $1::uuid AND role = $2`,
		groupID, role)
	return err
}
