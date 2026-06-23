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

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/internal/db"
)

// SubjectKindUser / SubjectKindRemoteApplication are the polymorphic subject
// kinds a group assignment may target (mirrors group_role_assignments).
const (
	SubjectKindUser      = "user"
	SubjectKindRemoteApp = "remote_application"
)

// ErrGroupNotFound is returned when a (persona, resource_slug) or id resolves to no
// live permission-group.
var ErrGroupNotFound = errors.New("permission group not found")

// PermissionGroupStore is the database access layer for permission-groups. It
// holds a db.DBTX (a *pgxpool.Pool or a pgx.Tx), so callers choose the txn scope.
type PermissionGroupStore struct {
	q db.DBTX
}

// NewPermissionGroupStore wraps a db.DBTX (pool or transaction).
func NewPermissionGroupStore(q db.DBTX) *PermissionGroupStore {
	return &PermissionGroupStore{q: q}
}

// SeedContainment upserts the containment schema (group_persona_parents) from a
// validated GroupSchema. Idempotent; call once at bootstrap so the DB trigger
// can enforce the declared tree shape. root has no rows (parentless).
func (st *PermissionGroupStore) SeedContainment(ctx context.Context, schema *GroupSchema) error {
	for _, persona := range schema.Personas() {
		if schema.IsRoot(persona) {
			continue
		}
		td, _ := schema.Persona(persona)
		for _, parent := range td.AllowedParents {
			if _, err := st.q.Exec(ctx,
				`INSERT INTO profiles.group_persona_parents (persona, allowed_parent_persona)
				 VALUES ($1, $2) ON CONFLICT DO NOTHING`,
				persona, parent); err != nil {
				return fmt.Errorf("seed containment %s<-%s: %w", persona, parent, err)
			}
		}
	}
	return nil
}

// CreateGroup inserts a permission-group and returns its internal id. parentID/
// parentPersona are empty for the root group. The containment trigger + CHECK
// enforce shape at the DB; callers SHOULD also pre-validate via
// GroupSchema.ValidateParent for a clear error before hitting the DB.
func (st *PermissionGroupStore) CreateGroup(ctx context.Context, persona, parentID, parentPersona, resourceSlug string) (string, error) {
	var id string
	err := st.q.QueryRow(ctx,
		`INSERT INTO profiles.permission_groups (persona, parent_id, parent_persona, resource_slug)
		 VALUES ($1, NULLIF($2,'')::uuid, NULLIF($3,''), NULLIF($4,''))
		 RETURNING id::text`,
		persona, parentID, parentPersona, resourceSlug).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create %q group: %w", persona, err)
	}
	return id, nil
}

// GroupByResourceSlug resolves a group by its API addressing key (persona,
// resource_slug) — the route layer's (persona, resource-id). Returns the internal
// id, which never leaves authkit.
func (st *PermissionGroupStore) GroupByResourceSlug(ctx context.Context, persona, resourceSlug string) (string, error) {
	var id string
	err := st.q.QueryRow(ctx,
		`SELECT id::text FROM profiles.permission_groups
		 WHERE persona = $1 AND resource_slug = $2 AND deleted_at IS NULL`,
		persona, resourceSlug).Scan(&id)
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
		`SELECT id::text FROM profiles.permission_groups WHERE persona = 'root' AND deleted_at IS NULL`).Scan(&id)
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
	rows, err := st.q.Query(ctx,
		`WITH RECURSIVE chain AS (
			SELECT id, persona, parent_id FROM profiles.permission_groups
			WHERE id = $1::uuid AND deleted_at IS NULL
			UNION ALL
			SELECT p.id, p.persona, p.parent_id FROM profiles.permission_groups p
			JOIN chain c ON p.id = c.parent_id WHERE p.deleted_at IS NULL
		)
		SELECT c.id::text, c.persona, a.role
		FROM chain c
		LEFT JOIN profiles.group_role_assignments a
		  ON a.group_id = c.id AND a.subject_id = $2::uuid
		     AND a.subject_kind = $3 AND a.deleted_at IS NULL
		ORDER BY c.id`,
		groupID, subjectID, subjectKind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type acc struct {
		typ   string
		roles []string
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
			a.roles = append(a.roles, *role)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []GroupAssignment
	for _, gid := range order {
		a := byGroup[gid]
		if len(a.roles) == 0 {
			continue // an ancestor where the subject holds nothing contributes no grants
		}
		out = append(out, GroupAssignment{Persona: a.typ, GroupID: gid, Roles: a.roles})
	}
	return out, nil
}

// AssignRole grants subject a role in a group, replacing any previous role in
// that same group. The role NAME is validated against the persona catalog / custom
// roles by the caller before assignment.
func (st *PermissionGroupStore) AssignRole(ctx context.Context, groupID, subjectID, subjectKind, role string) error {
	_, err := st.q.Exec(ctx,
		`WITH replaced AS (
		   UPDATE profiles.group_role_assignments
		      SET deleted_at = now(), updated_at = now()
		    WHERE group_id = $1::uuid AND subject_id = $2::uuid AND subject_kind = $3
		      AND role <> $4 AND deleted_at IS NULL
		 )
		 INSERT INTO profiles.group_role_assignments (group_id, subject_id, subject_kind, role)
		 VALUES ($1::uuid, $2::uuid, $3, $4)
		 ON CONFLICT (group_id, subject_id, subject_kind, role) WHERE deleted_at IS NULL
		 DO UPDATE SET updated_at = now()`,
		groupID, subjectID, subjectKind, role)
	return err
}

// UnassignRole soft-deletes a role assignment.
func (st *PermissionGroupStore) UnassignRole(ctx context.Context, groupID, subjectID, subjectKind, role string) error {
	_, err := st.q.Exec(ctx,
		`UPDATE profiles.group_role_assignments SET deleted_at = now(), updated_at = now()
		 WHERE group_id = $1::uuid AND subject_id = $2::uuid AND subject_kind = $3
		   AND role = $4 AND deleted_at IS NULL`,
		groupID, subjectID, subjectKind, role)
	return err
}

// UnassignSubject soft-deletes every active role assignment a subject holds in a group.
func (st *PermissionGroupStore) UnassignSubject(ctx context.Context, groupID, subjectID, subjectKind string) error {
	_, err := st.q.Exec(ctx,
		`UPDATE profiles.group_role_assignments SET deleted_at = now(), updated_at = now()
		 WHERE group_id = $1::uuid AND subject_id = $2::uuid AND subject_kind = $3
		   AND deleted_at IS NULL`,
		groupID, subjectID, subjectKind)
	return err
}

// UpsertCustomRole defines/updates a per-group custom role's permission set.
// Only meaningful for types whose AllowCustomRoles is set; the caller enforces
// that + validates each grant pattern (namespace-pure to the group's type).
func (st *PermissionGroupStore) UpsertCustomRole(ctx context.Context, groupID, role string, permissions []string) error {
	_, err := st.q.Exec(ctx,
		`INSERT INTO profiles.group_custom_roles (group_id, role, permissions)
		 VALUES ($1::uuid, $2, $3)
		 ON CONFLICT (group_id, role) DO UPDATE SET permissions = EXCLUDED.permissions, updated_at = now()`,
		groupID, role, permissions)
	return err
}

// CustomRolesFor preloads the custom roles for a set of group ids and returns a
// CustomRoleResolver backed by the result — so the pure decision core resolves
// custom-role grants without per-call DB access.
func (st *PermissionGroupStore) CustomRolesFor(ctx context.Context, groupIDs []string) (CustomRoleResolver, error) {
	if len(groupIDs) == 0 {
		return func(string, string) ([]string, bool) { return nil, false }, nil
	}
	rows, err := st.q.Query(ctx,
		`SELECT group_id::text, role, permissions FROM profiles.group_custom_roles
		 WHERE group_id = ANY($1::uuid[])`,
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
// action on a type-RT resource reached from an ancestor of type LT, the perm is
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
		ids = append(ids, a.GroupID)
	}
	resolver, err := st.CustomRolesFor(ctx, ids)
	if err != nil {
		return false, err
	}
	return schema.Can(asg, resolver, perm), nil
}

// GroupMember is one role-assignment in a group (roster listing).
type GroupMember struct {
	SubjectID   string
	SubjectKind string
	Role        string
}

// GroupMembers lists the live role-assignments in a group.
func (st *PermissionGroupStore) GroupMembers(ctx context.Context, groupID string) ([]GroupMember, error) {
	rows, err := st.q.Query(ctx,
		`SELECT subject_id::text, subject_kind, role FROM profiles.group_role_assignments
		 WHERE group_id = $1::uuid AND deleted_at IS NULL ORDER BY subject_id, role`, groupID)
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
type SubjectGroupMembership struct {
	Persona      string
	ResourceSlug string
	Role         string
}

// SubjectGroups lists every group membership a subject holds (cross-persona),
// the data behind /me/groups.
func (st *PermissionGroupStore) SubjectGroups(ctx context.Context, subjectID, subjectKind string) ([]SubjectGroupMembership, error) {
	rows, err := st.q.Query(ctx,
		`SELECT g.persona, COALESCE(g.resource_slug, ''), a.role
		 FROM profiles.group_role_assignments a
		 JOIN profiles.permission_groups g ON g.id = a.group_id AND g.deleted_at IS NULL
		 WHERE a.subject_id = $1::uuid AND a.subject_kind = $2 AND a.deleted_at IS NULL
		 ORDER BY g.persona, g.resource_slug, a.role`, subjectID, subjectKind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SubjectGroupMembership
	for rows.Next() {
		var m SubjectGroupMembership
		if err := rows.Scan(&m.Persona, &m.ResourceSlug, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeleteCustomRole removes a per-group custom role (and its permissions).
func (st *PermissionGroupStore) DeleteCustomRole(ctx context.Context, groupID, role string) error {
	_, err := st.q.Exec(ctx,
		`DELETE FROM profiles.group_custom_roles WHERE group_id = $1::uuid AND role = $2`,
		groupID, role)
	return err
}
