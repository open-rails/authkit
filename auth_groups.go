package authkit

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/engine"
	"github.com/open-rails/authkit/verify"
)

// Permission groups, roles and group invitations.

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

func (a *Auth) CreatePermissionGroup(ctx context.Context, req iam.CreatePermissionGroupRequest) (string, error) {
	return a.engine.CreatePermissionGroup(ctx, req)
}

func (a *Auth) ResolveGroupIDForSlug(ctx context.Context, group iam.GroupRef) (string, error) {
	return a.engine.ResolveGroupIDForSlug(ctx, group)
}

func (a *Auth) GroupInstanceForSlug(ctx context.Context, group iam.GroupRef) (iam.GroupInstance, error) {
	return a.engine.GroupInstanceForSlug(ctx, group)
}

func (a *Auth) UpdateGroupInstanceAs(ctx context.Context, actorUserID string, groupID string, update iam.GroupInstanceUpdate) (iam.GroupInstance, error) {
	return a.engine.UpdateGroupInstanceAs(ctx, actorUserID, groupID, update)
}

// SoftDeleteGroupInstanceByID retires a non-root group without removing its
// rows or name reservations. Repeated calls retain the original DeletedAt.
// The trusted host owns admission, retention and eventual hard deletion.
func (a *Auth) SoftDeleteGroupInstanceByID(ctx context.Context, groupID string) (iam.GroupInstance, error) {
	return a.engine.SoftDeleteGroupInstanceByID(ctx, groupID)
}

// DeleteGroupInstanceByID is a trusted host-operator mutation.
func (a *Auth) DeleteGroupInstanceByID(ctx context.Context, groupID string, opts iam.DeletePermissionGroupOptions) error {
	return a.engine.DeleteGroupInstanceByID(ctx, groupID, opts)
}

// GroupInstancesByIDs reads many resolved groups in ONE query, retained
// soft-deleted ones included (DeletedAt set); unknown ids are absent. At
// most MaxBatch distinct ids. GroupInstanceByID is its length-1 form.
func (a *Auth) GroupInstancesByIDs(ctx context.Context, groupIDs []string) (map[string]iam.GroupInstance, error) {
	return a.engine.GroupInstancesByIDs(ctx, groupIDs)
}

func (a *Auth) GroupInstanceByID(ctx context.Context, groupID string) (iam.GroupInstance, error) {
	return a.engine.GroupInstanceByID(ctx, groupID)
}

func (a *Auth) ListGroupMembers(ctx context.Context, group iam.GroupRef) ([]iam.GroupMember, error) {
	return a.engine.ListGroupMembers(ctx, group)
}

func (a *Auth) ListSubjectGroups(ctx context.Context, subject iam.Subject) ([]iam.SubjectGroupMembership, error) {
	return a.engine.ListSubjectGroups(ctx, subject)
}

// Can reports whether subject holds perm in group. An unregistered perm is
// iam.ErrUnknownPermission, never a silent false.
func (a *Auth) Can(ctx context.Context, subject iam.Subject, group iam.GroupRef, perm iam.Perm) (bool, error) {
	return a.engine.Can(ctx, subject, group, perm)
}

func (a *Auth) CanOnGroup(ctx context.Context, subject iam.Subject, groupID string, perm iam.Perm) (bool, error) {
	return a.engine.CanOnGroup(ctx, subject, groupID, perm)
}

// KnownPermission reports whether perm is registered in a persona catalog of
// Config.Roles, AuthKit's built-ins included.
func (a *Auth) KnownPermission(perm iam.Perm) bool { return a.engine.KnownPermission(perm) }

// RequirePermission authenticates the request and requires perm on the group
// resolve returns. It panics at construction on an unregistered perm.
func (a *Auth) RequirePermission(perm iam.Perm, resolve func(*http.Request) verify.PermissionScope) func(http.Handler) http.Handler {
	gate := verify.RequirePermission(a, perm, resolve)
	return func(next http.Handler) http.Handler { return a.Require(gate(next)) }
}

// EffectivePermissionsForGroups returns one subject's effective grant
// patterns on many resolved groups in ONE query, with ListEffectivePermissions
// semantics per group; groups granting nothing (unknown, soft-deleted, no
// assignment) are absent. At most MaxBatch distinct ids.
func (a *Auth) EffectivePermissionsForGroups(ctx context.Context, subject iam.Subject, groupIDs []string) (map[string][]iam.Perm, error) {
	return a.engine.EffectivePermissionsForGroups(ctx, subject, groupIDs)
}

func (a *Auth) ListEffectivePermissions(ctx context.Context, subject iam.Subject, group iam.GroupRef) ([]iam.Perm, error) {
	return a.engine.ListEffectivePermissions(ctx, subject, group)
}

func (a *Auth) CreateGroupInviteLink(ctx context.Context, req iam.CreateGroupInviteLinkRequest) (iam.GroupInviteLinkCreated, error) {
	return a.engine.CreateGroupInviteLink(ctx, req)
}

func (a *Auth) ListGroupInviteLinks(ctx context.Context, group iam.GroupRef) ([]iam.GroupInviteLink, error) {
	return a.engine.ListGroupInviteLinks(ctx, group)
}

func (a *Auth) RevokeGroupInviteLink(ctx context.Context, group iam.GroupRef, linkID string) error {
	return a.engine.RevokeGroupInviteLink(ctx, group, linkID)
}

// WithResolvedGroup binds a group address the host already resolved and
// authorized to its immutable target, so later name-addressed operations in
// ctx act on the same group even if the name is reclaimed. It confers no
// permission; every use rechecks the group is live.
func WithResolvedGroup(ctx context.Context, instance iam.GroupInstance, reference string) context.Context {
	return authflow.WithResolvedGroup(ctx, instance, reference)
}

// GroupDirectory reads immutable group identities and current/active alias
// names from an already migrated schema, without an Auth: it carries no
// signer, issuer or session state.
type GroupDirectory struct{ d *engine.GroupDirectory }

// NewGroupDirectory creates a read-only view of an already migrated schema.
// Empty schema selects the default profiles namespace. Construction does not
// query, migrate, write or start workers. Hosts remain responsible for
// authorizing any subsequent action.
func NewGroupDirectory(pool *pgxpool.Pool, schema string) (*GroupDirectory, error) {
	d, err := engine.NewGroupDirectory(pool, schema)
	if err != nil {
		return nil, err
	}
	return &GroupDirectory{d: d}, nil
}

// Close releases the directory's schema-bound pool. The caller's pool passed
// to NewGroupDirectory remains host-owned.
func (g *GroupDirectory) Close() {
	if g != nil {
		g.d.Close()
	}
}

func (g *GroupDirectory) GroupInstanceForSlug(ctx context.Context, group iam.GroupRef) (iam.GroupInstance, error) {
	return g.d.GroupInstanceForSlug(ctx, group)
}

func (g *GroupDirectory) GroupInstanceByID(ctx context.Context, id string) (iam.GroupInstance, error) {
	return g.d.GroupInstanceByID(ctx, id)
}

// SearchGroupInstances returns canonical slugs containing query (case
// insensitive, literal substring), ordered by (slug,id). Empty cursor starts
// the search; later pages use the last row's slug/id. Limit defaults to 50
// and is capped at 200.
func (g *GroupDirectory) SearchGroupInstances(ctx context.Context, persona iam.Persona, query, afterSlug, afterID string, limit int) ([]iam.GroupInstance, error) {
	return g.d.SearchGroupInstances(ctx, persona, query, afterSlug, afterID, limit)
}
