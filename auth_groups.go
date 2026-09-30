package authkit

import (
	"context"

	"github.com/open-rails/authkit/iam"
)

// Permission groups, roles and permission checks.

// Roles. Every mutation takes an iam.Actor and is checked by the engine: a
// user subject needs <persona>:members:manage, an application subject
// <persona>:credentials:manage, and the actor must cover every role it grants
// or takes away. iam.SystemActor() skips those rules; the last usable owner
// and MFA-required roles bind everyone. A subject holds at most one role in a
// group.

// SetGroupRole makes subject hold role in ref, replacing the role it holds.
// Holding role already changes nothing.
func (a *Client) SetGroupRole(ctx context.Context, actor iam.Actor, ref iam.GroupRef, subject iam.Subject, role iam.Role, opts ...Option) (iam.GroupMember, error) {
	return a.ops.SetGroupRole(ctx, actor, ref, subject, role, opts...)
}

// RemoveGroupMember takes subject's role in ref away; removing a non-member
// changes nothing. With IfRole, a subject holding another role keeps it.
func (a *Client) RemoveGroupMember(ctx context.Context, actor iam.Actor, ref iam.GroupRef, subject iam.Subject, opts ...Option) error {
	return a.ops.RemoveGroupMember(ctx, actor, ref, subject, opts...)
}

// GroupRoles returns the direct role of each subject holding one in the group,
// for any number of subjects. Subjects without a role are absent.
func (a *Client) GroupRoles(ctx context.Context, ref iam.GroupRef, subjects []iam.Subject) (map[iam.Subject]iam.Role, error) {
	return a.ops.GroupRoles(ctx, ref, subjects)
}

// Groups. A persona is a type of permission group (channel, org, merchant); a
// group is one instance of it, addressed by ID; root is the persona with
// exactly one group, the whole site. Reads take no actor: the host is the
// trust boundary.

// Group reads one group, a soft-deleted one included, with DeletedAt set.
// Absence is iam.ErrGroupNotFound.
func (a *Client) Group(ctx context.Context, ref iam.GroupRef) (iam.Group, error) {
	return a.ops.Group(ctx, ref)
}

// Groups reads any number of groups by id, soft-deleted ones included.
// Unknown ids are absent.
func (a *Client) Groups(ctx context.Context, ids []string) (map[string]iam.Group, error) {
	return a.ops.Groups(ctx, ids)
}

// ListGroups lists the groups of a persona, oldest first, a page at a time.
func (a *Client) ListGroups(ctx context.Context, q iam.GroupQuery) (iam.ListPage[iam.Group], error) {
	return a.ops.ListGroups(ctx, q)
}

// ListGroupMembers lists the subjects holding a role in a group, a page at a
// time.
func (a *Client) ListGroupMembers(ctx context.Context, ref iam.GroupRef, q iam.MemberQuery) (iam.ListPage[iam.GroupMember], error) {
	return a.ops.ListGroupMembers(ctx, ref, q)
}

// ListMemberships lists the live groups a subject holds a role in, a page at
// a time.
func (a *Client) ListMemberships(ctx context.Context, s iam.Subject, p iam.PageRequest) (iam.ListPage[iam.Membership], error) {
	return a.ops.ListMemberships(ctx, s, p)
}

// Group lifecycle. A group guards an entity of your app (a channel); the app
// owns that entity and its data, and stores the group's ID or keys the group
// by an id of its own (NewGroup.ID). These are host operations: your code
// decides who may create or delete one, checking its own permissions first,
// so they take no actor. Pass InTx to create or delete the group in the same
// transaction as your own row.

// CreateGroup creates a group of a declared persona. g.Owner, when set, must
// be a live account (not banned or deleted); it becomes the new
// group's owner. With g.ID it is idempotent: creating a live group of the
// same persona returns it unchanged, while a deleted group or one of another
// persona under that id is iam.ErrGroupConflict.
func (a *Client) CreateGroup(ctx context.Context, g iam.NewGroup, opts ...Option) (iam.Group, error) {
	return a.ops.CreateGroup(ctx, g, opts...)
}

// DeleteGroup soft-deletes a group: it stops resolving and granting at once,
// while its rows stay until PurgeGroup. Deleting a deleted group is a no-op.
func (a *Client) DeleteGroup(ctx context.Context, ref iam.GroupRef, opts ...Option) error {
	return a.ops.DeleteGroup(ctx, ref, opts...)
}

// PurgeGroup permanently deletes a group, live or soft-deleted, with every
// role, API key, invitation and application in it. Purging an unknown group
// is a no-op.
func (a *Client) PurgeGroup(ctx context.Context, ref iam.GroupRef, opts ...Option) error {
	return a.ops.PurgeGroup(ctx, ref, opts...)
}

// Can reports whether actor holds perm in the group, checked live: a banned
// or deleted user, a revoked key, an unknown group or an actor bound to
// another group is false. An actor built from a token
// (verify.ActorFromClaims) is bound to its session: once that session or
// device key is revoked, Can is iam.ErrSessionRevoked. An unregistered perm is
// iam.ErrUnknownPermission, never a silent false.
func (a *Client) Can(ctx context.Context, actor iam.Actor, ref iam.GroupRef, perm iam.Perm) (bool, error) {
	return a.ops.Can(ctx, actor, ref, perm)
}

// EffectivePermissions returns actor's effective grant patterns per group id
// (globs verbatim, glob-match with iam.Perm.Matches), for any number of groups.
// Groups granting nothing are absent.
func (a *Client) EffectivePermissions(ctx context.Context, actor iam.Actor, refs []iam.GroupRef) (map[string][]iam.Perm, error) {
	return a.ops.EffectivePermissions(ctx, actor, refs)
}

// KnownPermission reports whether perm is registered in a persona catalog of
// Config.Roles, AuthKit's built-ins included.
func (a *Client) KnownPermission(perm iam.Perm) bool { return a.ops.KnownPermission(perm) }

// Names read at run time (a request parameter, a config file, a stored row
// of the host's) become typed values only through the schema.

// Persona resolves a persona name: iam.ErrUnknownGroupPersona unless
// Config.Roles declares it (root always is).
func (a *Client) Persona(name string) (iam.Persona, error) { return a.ops.Persona(name) }

// Permission resolves a concrete permission: iam.ErrUnknownPermission unless
// it is registered.
func (a *Client) Permission(text string) (iam.Perm, error) { return a.ops.Permission(text) }

// Role resolves role text `<persona>:<name>` (`channel:moderator`), the one
// text form of a role: a declared role or a persona's owner role, else
// iam.ErrRoleNotAssignable.
func (a *Client) Role(text string) (iam.Role, error) { return a.ops.Role(text) }

// RolePermissions returns role's grants in Config.Roles, includes flattened:
// permissions and patterns (`channel:*`), matched with iam.Perm.Matches. A
// role the catalog does not declare is iam.ErrRoleNotAssignable
// (iam.ErrUnknownGroupPersona for an undeclared persona).
func (a *Client) RolePermissions(role iam.Role) ([]iam.Perm, error) {
	return a.ops.RolePermissions(role)
}
