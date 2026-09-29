package authkit

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
)

// Permission groups, roles and group invitations.

// OperatorAssignGroupRole and OperatorUnassignGroupRole use trusted host-operator
// authority, not a persona or role named operator. Hosts authorize the operator; request
// actors use the corresponding actor-checked *As methods. Subject MFA and
// final-owner invariants still apply. These methods add no HTTP exposure.
func (a *Auth) OperatorAssignGroupRole(ctx context.Context, group iam.GroupRef, subject iam.Subject, role iam.Role) error {
	return a.engine.OperatorAssignGroupRole(ctx, group, subject, role)
}

func (a *Auth) OperatorUnassignGroupRole(ctx context.Context, group iam.GroupRef, subject iam.Subject, role iam.Role) error {
	return a.engine.OperatorUnassignGroupRole(ctx, group, subject, role)
}

// Assign/RemoveRolesBySlugAs are batch-native (#219/#222): the no-escalation
// check (#136) runs PER ITEM and each OpResult carries its own authority error.
func (a *Auth) AssignRolesBySlugAs(ctx context.Context, actorUserID string, userIDs []string, role iam.Role) ([]iam.OpResult, error) {
	return a.engine.AssignRolesBySlugAs(ctx, actorUserID, userIDs, role)
}

func (a *Auth) RemoveRolesBySlugAs(ctx context.Context, actorUserID string, userIDs []string, role iam.Role) ([]iam.OpResult, error) {
	return a.engine.RemoveRolesBySlugAs(ctx, actorUserID, userIDs, role)
}

func (a *Auth) UpsertRoleBySlug(ctx context.Context, name string, role iam.Role, description *string) error {
	return a.engine.UpsertRoleBySlug(ctx, name, role, description)
}

// RoleSlugsByUsers returns each user's LIVE configured root role slugs in
// ONE call (#220); users with no roles are absent; errors PROPAGATE (#136).
func (a *Auth) RoleSlugsByUsers(ctx context.Context, userIDs []string) (map[string][]string, error) {
	return a.engine.RoleSlugsByUsers(ctx, userIDs)
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

// SoftDeleteGroupInstanceByID retires a nonroot subtree without removing its
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
// most MaxGroupBatch distinct ids. GroupInstanceByID is its length-1 form.
func (a *Auth) GroupInstancesByIDs(ctx context.Context, groupIDs []string) (map[string]iam.GroupInstance, error) {
	return a.engine.GroupInstancesByIDs(ctx, groupIDs)
}

func (a *Auth) GroupInstanceByID(ctx context.Context, groupID string) (iam.GroupInstance, error) {
	return a.engine.GroupInstanceByID(ctx, groupID)
}

func (a *Auth) AssignGroupRoleAs(ctx context.Context, actorUserID string, group iam.GroupRef, subject iam.Subject, role iam.Role) error {
	return a.engine.AssignGroupRoleAs(ctx, actorUserID, group, subject, role)
}

func (a *Auth) UnassignGroupRoleAs(ctx context.Context, actorUserID string, group iam.GroupRef, subject iam.Subject, role iam.Role) error {
	return a.engine.UnassignGroupRoleAs(ctx, actorUserID, group, subject, role)
}

func (a *Auth) RemoveGroupSubjectAs(ctx context.Context, actorUserID string, group iam.GroupRef, subject iam.Subject) error {
	return a.engine.RemoveGroupSubjectAs(ctx, actorUserID, group, subject)
}

func (a *Auth) ListGroupMembers(ctx context.Context, group iam.GroupRef) ([]iam.GroupMember, error) {
	return a.engine.ListGroupMembers(ctx, group)
}

func (a *Auth) ListSubjectGroups(ctx context.Context, subject iam.Subject) ([]iam.SubjectGroupMembership, error) {
	return a.engine.ListSubjectGroups(ctx, subject)
}

func (a *Auth) Can(ctx context.Context, subject iam.Subject, group iam.GroupRef, perm iam.Perm) (bool, error) {
	return a.engine.Can(ctx, subject, group, perm)
}

func (a *Auth) CanOnGroup(ctx context.Context, subject iam.Subject, groupID string, perm iam.Perm) (bool, error) {
	return a.engine.CanOnGroup(ctx, subject, groupID, perm)
}

// EffectivePermissionsForGroups returns one subject's effective grant
// patterns on many resolved groups in ONE query, with ListEffectivePermissions
// semantics per group; groups granting nothing (unknown, soft-deleted, no
// assignment) are absent. At most MaxGroupBatch distinct ids.
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
