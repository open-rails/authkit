package authkit

import (
	"context"
	"net/http"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

// Permission groups, roles and permission checks.

// Roles. Every mutation takes an iam.Actor and is checked by the engine: a
// user subject needs <persona>:members:manage, an application subject
// <persona>:credentials:manage, and the actor must cover every role it grants
// or takes away. iam.OperatorActor() skips those rules; the last usable owner
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
// group is one instance of it (/c/golang); root is the persona with exactly
// one group, the whole site. Reads take no actor: the host is the trust
// boundary.

// Group reads one group. A slug resolves only a live group; an id also
// returns a soft-deleted one, with DeletedAt set. Absence is
// iam.ErrGroupNotFound.
func (a *Auth) Group(ctx context.Context, ref iam.GroupRef) (iam.Group, error) {
	return a.engine.Group(ctx, ref)
}

// Groups reads many groups by id in one query, soft-deleted ones included.
// Unknown ids are absent. At most iam.MaxBatch ids.
func (a *Auth) Groups(ctx context.Context, ids []string) (map[string]iam.Group, error) {
	return a.engine.Groups(ctx, ids)
}

// ListGroups lists and searches groups, ordered by slug, a page at a time.
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

// CreateGroup creates a group. A user actor creates a group of a persona
// whose GroupCreation is enabled and becomes its owner; a reserved slug needs
// `<persona>:*` held on root, and the host's admission hooks apply. An
// operator may create a group of any persona, with NewGroup.Owner or no
// owner. created is false when the slug already exists and the owner is a
// member: a re-run returns the existing group.
func (a *Auth) CreateGroup(ctx context.Context, actor iam.Actor, g iam.NewGroup) (group iam.Group, created bool, err error) {
	return a.engine.CreateGroup(ctx, actor, g)
}

// UpdateGroup renames a group or changes its display name. It needs
// `<persona>:self:update`.
func (a *Auth) UpdateGroup(ctx context.Context, actor iam.Actor, ref iam.GroupRef, u iam.GroupUpdate) (iam.Group, error) {
	return a.engine.UpdateGroup(ctx, actor, ref, u)
}

// DeleteGroup soft-deletes a group: it stops resolving and granting, while its
// rows and slug stay reserved. It needs `<persona>:self:delete`.
func (a *Auth) DeleteGroup(ctx context.Context, actor iam.Actor, ref iam.GroupRef) (iam.Group, error) {
	return a.engine.DeleteGroup(ctx, actor, ref)
}

// PurgeGroup permanently deletes a group, live or soft-deleted (address it by
// id), with everything in it. Only iam.OperatorActor() may purge.
func (a *Auth) PurgeGroup(ctx context.Context, actor iam.Actor, ref iam.GroupRef, o iam.PurgeGroupOptions) error {
	return a.engine.PurgeGroup(ctx, actor, ref, o)
}

// DefineGroupRole creates or redefines a custom role in a group whose persona
// has CustomRoles. It needs `<persona>:roles:manage` and must cover the old
// and new permissions; redefining a role users hold also needs
// `<persona>:members:manage`, and one API keys or applications hold
// `<persona>:credentials:manage`.
func (a *Auth) DefineGroupRole(ctx context.Context, actor iam.Actor, ref iam.GroupRef, r iam.CustomRole) error {
	return a.engine.DefineGroupRole(ctx, actor, ref, r)
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

// RequirePermission authenticates the request (it includes Require) and
// requires perm in group, checked live. For a group taken from the request,
// use verify.RequirePermission or an adapter's RequirePermission with a
// resolver. It panics at construction on an unregistered perm.
func (a *Auth) RequirePermission(group iam.GroupRef, perm iam.Perm) func(http.Handler) http.Handler {
	return verify.RequirePermission(a, perm, func(*http.Request) iam.GroupRef { return group })
}
