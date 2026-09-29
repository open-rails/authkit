package authkit

import (
	"context"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

// Permission groups, roles and permission checks.

// Roles. Every mutation takes an iam.Actor and is checked by the engine: a
// user subject needs <persona>:members:manage, an application subject
// <persona>:credentials:manage, and the actor must cover every role it grants
// or takes away. iam.SystemActor() skips those rules; the last usable owner
// and MFA-required roles bind everyone. Items fail independently: each
// OpResult carries its own error, while the error return is for the whole call
// (zero actor, unknown group, unassignable role, dead actor).

// AssignGroupRoles assigns role to each subject, replacing the role it holds.
func (a *Auth) AssignGroupRoles(ctx context.Context, actor iam.Actor, ref iam.GroupRef, subjects []iam.Subject, role iam.Role) ([]iam.OpResult, error) {
	return a.engine.AssignGroupRoles(ctx, actor, ref, subjects, role)
}

// UnassignGroupRoles revokes role from each subject holding it.
func (a *Auth) UnassignGroupRoles(ctx context.Context, actor iam.Actor, ref iam.GroupRef, subjects []iam.Subject, role iam.Role) ([]iam.OpResult, error) {
	return a.engine.UnassignGroupRoles(ctx, actor, ref, subjects, role)
}

// RemoveGroupMembers strips each subject's role in the group.
func (a *Auth) RemoveGroupMembers(ctx context.Context, actor iam.Actor, ref iam.GroupRef, subjects []iam.Subject) ([]iam.OpResult, error) {
	return a.engine.RemoveGroupMembers(ctx, actor, ref, subjects)
}

// GroupRoles returns the direct role of each subject holding one in the group
// (at most iam.MaxBatch subjects). Subjects without a role are absent.
func (a *Auth) GroupRoles(ctx context.Context, ref iam.GroupRef, subjects []iam.Subject) (map[iam.Subject]iam.Role, error) {
	return a.engine.GroupRoles(ctx, ref, subjects)
}

// Groups. A persona is a type of permission group (channel, org, merchant); a
// group is one instance of it, addressed by ID; root is the persona with
// exactly one group, the whole site. Reads take no actor: the host is the
// trust boundary.

// Group reads one group, a soft-deleted one included, with DeletedAt set.
// Absence is iam.ErrGroupNotFound.
func (a *Auth) Group(ctx context.Context, ref iam.GroupRef) (iam.Group, error) {
	return a.engine.Group(ctx, ref)
}

// Groups reads many groups by id in one query, soft-deleted ones included.
// Unknown ids are absent. At most iam.MaxBatch ids.
func (a *Auth) Groups(ctx context.Context, ids []string) (map[string]iam.Group, error) {
	return a.engine.Groups(ctx, ids)
}

// ListGroups lists the groups of a persona, oldest first, a page at a time.
func (a *Auth) ListGroups(ctx context.Context, q iam.GroupQuery) (iam.ListPage[iam.Group], error) {
	return a.engine.ListGroups(ctx, q)
}

// ListGroupMembers lists the subjects holding a role in a group, a page at a
// time.
func (a *Auth) ListGroupMembers(ctx context.Context, ref iam.GroupRef, q iam.MemberQuery) (iam.ListPage[iam.GroupMember], error) {
	return a.engine.ListGroupMembers(ctx, ref, q)
}

// ListSubjectGroups lists the live groups a subject holds a role in, a page at
// a time.
func (a *Auth) ListSubjectGroups(ctx context.Context, s iam.Subject, p iam.PageRequest) (iam.ListPage[iam.Membership], error) {
	return a.engine.ListSubjectGroups(ctx, s, p)
}

// OwnerlessGroups lists the live groups, root aside, that no owner counts for
// under the last-owner rule, a page at a time: groups created without one, or
// left without one by the credential sweep at boot, which only logs it. An
// owner whose required MFA enrollment is pending does not count. Assign one
// with AssignGroupRoles.
func (a *Auth) OwnerlessGroups(ctx context.Context, p iam.PageRequest) (iam.ListPage[iam.Group], error) {
	return a.engine.OwnerlessGroups(ctx, p)
}

// Group lifecycle. A group guards an entity of your app (a channel); the app
// owns that entity, its name and its data, and stores the group's ID. These
// are host operations: your code decides who may create or delete one,
// checking its own permissions first, so they take no actor. Pass InTx to
// create or delete the group in the same transaction as your own row.

// CreateGroup creates a group of a declared persona. g.Owner, when set, must
// be a live account (not banned, deleted or reserved); it becomes the
// group's owner.
func (a *Auth) CreateGroup(ctx context.Context, g iam.NewGroup, opts ...Option) (iam.Group, error) {
	return a.engine.CreateGroup(ctx, g, options(opts).tx)
}

// DeleteGroup soft-deletes a group: it stops resolving and granting at once,
// while its rows stay until PurgeGroup. Deleting a deleted group is a no-op.
func (a *Auth) DeleteGroup(ctx context.Context, ref iam.GroupRef, opts ...Option) error {
	return a.engine.DeleteGroup(ctx, ref, options(opts).tx)
}

// PurgeGroup permanently deletes a group, live or soft-deleted, with every
// role, custom role, API key, invite and application in it. Purging an
// unknown group is a no-op.
func (a *Auth) PurgeGroup(ctx context.Context, ref iam.GroupRef, opts ...Option) error {
	return a.engine.PurgeGroup(ctx, ref, options(opts).tx)
}

// Option adjusts one operation.
type Option func(*operationOptions)

type operationOptions struct{ tx pgx.Tx }

func options(opts []Option) operationOptions {
	var o operationOptions
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// InTx runs the operation inside tx, the host's own transaction, so AuthKit's
// changes commit or roll back with the host's: a group and the app row that
// stores its ID, or neither. tx must be a READ COMMITTED transaction on the
// database of Deps.Postgres; AuthKit's schema needs no search_path entry.
// AuthKit works in a savepoint of tx: a refused operation rolls back to it and
// leaves tx usable. Its authority lock, the credential sweep and its event
// records are all part of tx, and the lock is held until tx ends, so commit
// promptly.
func InTx(tx pgx.Tx) Option { return func(o *operationOptions) { o.tx = tx } }

// DefineGroupRole creates or redefines the custom role name, holding perms
// (permissions or patterns of the persona), in a group whose persona has
// CustomRoles, and returns it. It needs `<persona>:roles:manage` and must
// cover the old and new permissions; redefining a role users hold also needs
// `<persona>:members:manage`, and one API keys or applications hold
// `<persona>:credentials:manage`.
func (a *Auth) DefineGroupRole(ctx context.Context, actor iam.Actor, ref iam.GroupRef, name string, perms ...iam.Perm) (iam.Role, error) {
	return a.engine.DefineGroupRole(ctx, actor, ref, name, perms...)
}

// DeleteGroupRole deletes a custom role and every reference to it, under
// DefineGroupRole's rule.
func (a *Auth) DeleteGroupRole(ctx context.Context, actor iam.Actor, ref iam.GroupRef, role iam.Role) error {
	return a.engine.DeleteGroupRole(ctx, actor, ref, role)
}

// Can reports whether actor holds perm in the group, checked live: a banned
// or deleted user, a revoked key, an unknown group or an actor bound to
// another group is false. An unregistered perm is iam.ErrUnknownPermission,
// never a silent false.
func (a *Auth) Can(ctx context.Context, actor iam.Actor, ref iam.GroupRef, perm iam.Perm) (bool, error) {
	return a.engine.Can(ctx, actor, ref, perm)
}

// EffectivePermissions returns actor's effective grant patterns per group id
// (globs verbatim, glob-match with iam.Perm.Matches). Groups granting nothing
// are absent. At most iam.MaxBatch groups.
func (a *Auth) EffectivePermissions(ctx context.Context, actor iam.Actor, refs []iam.GroupRef) (map[string][]iam.Perm, error) {
	return a.engine.EffectivePermissions(ctx, actor, refs)
}

// KnownPermission reports whether perm is registered in a persona catalog of
// Config.Roles, AuthKit's built-ins included.
func (a *Auth) KnownPermission(perm iam.Perm) bool { return a.engine.KnownPermission(perm) }

// Names read at run time (a request parameter, a config file, a stored row
// of the host's) become typed values only through the schema.

// Persona resolves a persona name: iam.ErrUnknownGroupPersona unless
// Config.Roles declares it (root always is).
func (a *Auth) Persona(name string) (iam.Persona, error) {
	p, ok := a.engine.PermissionGroupSchema().PersonaNamed(name)
	if !ok {
		return iam.Persona{}, fmt.Errorf("persona %q: %w", name, iam.ErrUnknownGroupPersona)
	}
	return p, nil
}

// Permission resolves a concrete permission: iam.ErrUnknownPermission unless
// it is registered.
func (a *Auth) Permission(text string) (iam.Perm, error) {
	p, ok := a.engine.PermissionGroupSchema().Permission(text)
	if !ok {
		return iam.Perm{}, fmt.Errorf("%w: %q", iam.ErrUnknownPermission, text)
	}
	return p, nil
}

// Role resolves a role name for groups of persona: a declared role or the
// owner role, else iam.ErrRoleNotAssignable. When the persona has
// CustomRoles, any valid name resolves; whether a group defines it is checked
// where the role is used.
func (a *Auth) Role(persona iam.Persona, name string) (iam.Role, error) {
	return a.engine.PermissionGroupSchema().ParseRole(persona, name)
}

// RequirePermission authenticates the request (it includes Require) and
// requires perm in group, checked live. For a group taken from the request,
// use verify.RequirePermission or an adapter's RequirePermission with a
// resolver. It panics at construction on an unregistered perm.
func (a *Auth) RequirePermission(group iam.GroupRef, perm iam.Perm) func(http.Handler) http.Handler {
	return verify.RequirePermission(a, perm, func(*http.Request) iam.GroupRef { return group })
}
