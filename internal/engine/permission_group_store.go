package engine

// DB-backed engine for the permission-group model (#111): the store loads the
// subject's assignments on a target group and on root, and feeds the pure
// decision core (rbac.Schema.Can). It runs the generated queries over a
// db.DBTX (pool or tx); unqualified table names resolve through the
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
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/rbac"
)

// requireGroupSubjectKind: role assignments exist for users and applications.
func requireGroupSubjectKind(kind iam.SubjectKind) error {
	if kind == iam.SubjectKindUser || kind == iam.SubjectKindRemoteApplication {
		return nil
	}
	return invalidSubjectKind(kind)
}

func invalidSubjectKind(kind iam.SubjectKind) error {
	return fmt.Errorf("invalid group subject kind %q", kind)
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

// CreateGroup inserts a non-root permission group and returns its id.
func (st *permissionGroupStore) CreateGroup(ctx context.Context, id string, persona iam.Persona) (string, error) {
	var err error
	if id == "" {
		id, err = db.New(st.q).PermissionGroupInsert(ctx, persona.String())
	} else {
		err = db.New(st.q).PermissionGroupInsertWithID(ctx, db.PermissionGroupInsertWithIDParams{ID: id, Persona: persona.String()})
	}
	if err != nil {
		return "", fmt.Errorf("create %q group: %w", persona, err)
	}
	return id, st.record(ctx, groupEvent(iam.EventGroupCreated, id, persona))
}

// lockGroup locks a group row for its permanent delete and returns its
// persona. The root group cannot be deleted.
func (st *permissionGroupStore) lockGroup(ctx context.Context, groupID string) (iam.Persona, error) {
	group, err := db.New(st.q).PermissionGroupForUpdate(ctx, groupID)
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.Persona{}, iam.ErrGroupNotFound
	}
	if err != nil {
		return iam.Persona{}, err
	}
	persona := ident.Persona(group.Persona)
	if persona == iam.RootPersona {
		return iam.Persona{}, fmt.Errorf("the root group cannot be deleted: %w", iam.ErrUnknownGroupPersona)
	}
	return persona, nil
}

func (st *permissionGroupStore) DeleteGroup(ctx context.Context, groupID string) error {
	persona, err := st.lockGroup(ctx, groupID)
	if err != nil {
		return err
	}
	if err := db.New(st.q).PermissionGroupDelete(ctx, groupID); err != nil {
		return err
	}
	return st.record(ctx, groupEvent(iam.EventGroupPurged, groupID, persona))
}

// RootGroupID returns the singleton root group's internal id (ErrGroupNotFound
// if the deployment has not seeded one yet).
func (st *permissionGroupStore) RootGroupID(ctx context.Context) (string, error) {
	id, err := db.New(st.q).PermissionGroupRootID(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", iam.ErrGroupNotFound
	}
	return id, err
}

// WalkAssignments returns the subject's assignments on the target group and on
// root: exactly what rbac.Schema.ResolveGrants/Can consume.
func (st *permissionGroupStore) WalkAssignments(ctx context.Context, groupID string, subject iam.Subject) ([]rbac.Assignment, error) {
	byGroup, err := st.readAssignmentsForGroups(ctx, []string{groupID}, subject)
	if err != nil {
		return nil, err
	}
	return byGroup[groupID], nil
}

// readAssignmentsForGroups reads, for every live target, the subject's
// assignments on that group and on root, in one query. Deleted, unknown and
// malformed targets have no assignments; an application's count only while it
// is enabled and its control group is live. Latent assignments of
// deleted/reserved accounts are included.
func (st *permissionGroupStore) readAssignmentsForGroups(ctx context.Context, groupIDs []string, subject iam.Subject) (map[string][]rbac.Assignment, error) {
	if err := requireGroupSubjectKind(subject.Kind); err != nil {
		return nil, err
	}
	out := map[string][]rbac.Assignment{}
	ids := groupBatchIDs(groupIDs)
	if len(ids) == 0 {
		return out, nil
	}
	q := db.New(st.q)
	arg := db.GroupUserAssignmentsForGroupsParams{SubjectID: subject.ID, GroupIds: ids}
	var rows []db.GroupUserAssignmentsForGroupsRow
	var err error
	if subject.Kind == iam.SubjectKindUser {
		rows, err = q.GroupUserAssignmentsForGroups(ctx, arg)
	} else {
		var apps []db.GroupApplicationAssignmentsForGroupsRow
		apps, err = q.GroupApplicationAssignmentsForGroups(ctx, db.GroupApplicationAssignmentsForGroupsParams(arg))
		for _, r := range apps {
			rows = append(rows, db.GroupUserAssignmentsForGroupsRow(r))
		}
	}
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		persona := ident.Persona(r.Persona)
		out[r.Target] = append(out[r.Target], rbac.Assignment{PermissionGroupID: r.GroupID, Persona: persona, Role: ident.RoleText(r.Role)})
	}
	return out, nil
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

// AssignRole replaces the current role for a group and subject. The composite
// primary key enforces one assignment; callers validate the role definition.
// Assigning the role already held changes nothing.
func (st *permissionGroupStore) AssignRole(ctx context.Context, groupID string, subject iam.Subject, role iam.Role) error {
	q := db.New(st.q)
	if subject.Kind == iam.SubjectKindRemoteApplication && role.IsOwner() {
		operable, err := q.RemoteApplicationEnabledInGroup(ctx, db.RemoteApplicationEnabledInGroupParams{ID: subject.ID, GroupID: groupID})
		if err != nil {
			return err
		}
		if !operable {
			return iam.ErrInsufficientAuthority
		}
	}
	if err := requireGroupSubjectKind(subject.Kind); err != nil {
		return err
	}
	group, err := q.PermissionGroupLiveForUpdate(ctx, groupID)
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.ErrGroupNotFound
	}
	if err != nil {
		return err
	}
	persona := ident.Persona(group.Persona)
	if role.Persona() != persona {
		return fmt.Errorf("role %q is not a role of a %q group: %w", role, persona, iam.ErrRoleNotAssignable)
	}
	previous, err := st.directRole(ctx, groupTarget{ID: groupID, Persona: persona}, subject)
	if err != nil || previous == role {
		return err
	}
	if subject.Kind == iam.SubjectKindUser {
		err = q.GroupUserRoleUpsert(ctx, db.GroupUserRoleUpsertParams{GroupID: groupID, UserID: subject.ID, Role: role.String()})
	} else {
		err = q.GroupApplicationRoleUpsert(ctx, db.GroupApplicationRoleUpsertParams{GroupID: groupID, ApplicationID: subject.ID, Role: role.String()})
	}
	if err != nil {
		return err
	}
	st.touch(groupID, subject)
	return st.record(ctx, roleEvent(groupID, persona, subject, previous, role))
}

// UnassignRole deletes the matching current assignment.
func (st *permissionGroupStore) UnassignRole(ctx context.Context, groupID string, subject iam.Subject, role iam.Role) error {
	name := role.String()
	return st.unassign(ctx, groupID, subject, &name)
}

// UnassignSubject deletes the subject's current assignment in this group.
func (st *permissionGroupStore) UnassignSubject(ctx context.Context, groupID string, subject iam.Subject) error {
	return st.unassign(ctx, groupID, subject, nil)
}

// unassign deletes the subject's assignment in the group; role, when set,
// must match.
func (st *permissionGroupStore) unassign(ctx context.Context, groupID string, subject iam.Subject, role *string) error {
	q := db.New(st.q)
	var deleted db.GroupUserRoleDeleteRow
	var err error
	switch subject.Kind {
	case iam.SubjectKindUser:
		deleted, err = q.GroupUserRoleDelete(ctx, db.GroupUserRoleDeleteParams{GroupID: groupID, UserID: subject.ID, Role: role})
	case iam.SubjectKindRemoteApplication:
		var app db.GroupApplicationRoleDeleteRow
		app, err = q.GroupApplicationRoleDelete(ctx, db.GroupApplicationRoleDeleteParams{GroupID: groupID, ApplicationID: subject.ID, Role: role})
		deleted = db.GroupUserRoleDeleteRow(app)
	default:
		return invalidSubjectKind(subject.Kind)
	}
	st.touch(groupID, subject)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	persona := ident.Persona(deleted.Persona)
	return st.record(ctx, roleEvent(groupID, persona, subject, ident.RoleText(deleted.Role), iam.Role{}))
}

// OwnerCount returns the count of live, unbanned, unreserved user owners and
// enabled application owners. Lifecycle safety uses the transaction-bound
// engine guard, which also checks the deployment's MFA policy.
func (st *permissionGroupStore) OwnerCount(ctx context.Context, groupID string) (int, error) {
	n, err := db.New(st.q).PermissionGroupOwnerCount(ctx, groupID)
	return int(n), err
}

// GrantsOnGroups returns, per live target group, the de-duplicated UNION of
// grant PATTERNS the subject holds on that group and on root, resolved
// against the schema's catalog, in one query. Globs
// like `root:*` are returned verbatim, not expanded. Targets granting nothing
// are absent. Latent assignments of deleted/reserved accounts are included.
func (st *permissionGroupStore) GrantsOnGroups(ctx context.Context, schema *rbac.Schema, subject iam.Subject, groupIDs []string) (map[string][]string, error) {
	byGroup, err := st.readAssignmentsForGroups(ctx, groupIDs, subject)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(byGroup))
	for gid, assignments := range byGroup {
		if grants := schema.ResolveGrants(gid, assignments); len(grants) > 0 {
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
	rows, err := db.New(st.q).PermissionGroupsByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.ID] = publicGroup(r)
	}
	return out, nil
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

// publicGroup projects a permission_groups row.
func publicGroup(r db.PermissionGroup) iam.Group {
	return iam.Group{ID: r.ID, Persona: ident.Persona(r.Persona), CreatedAt: r.CreatedAt, DeletedAt: r.DeletedAt}
}
