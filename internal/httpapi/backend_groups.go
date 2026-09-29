package httpapi

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/rbac"
)

// groupsBackend is permission groups, roles and permission checks.
type groupsBackend interface {
	Can(ctx context.Context, subject iam.Subject, group iam.GroupRef, perm iam.Perm) (bool, error)
	CanOnGroup(ctx context.Context, subject iam.Subject, groupID string, perm iam.Perm) (bool, error)
	GroupInstanceForSlug(ctx context.Context, group iam.GroupRef) (iam.GroupInstance, error)
	ListEffectivePermissions(ctx context.Context, subject iam.Subject, group iam.GroupRef) ([]iam.Perm, error)
	ListGroupMembers(ctx context.Context, group iam.GroupRef) ([]iam.GroupMember, error)
	ListSubjectGroups(ctx context.Context, subject iam.Subject) ([]iam.SubjectGroupMembership, error)
	AssignGroupRoles(ctx context.Context, a iam.Actor, group iam.GroupRef, subjects []iam.Subject, role iam.Role) ([]iam.OpResult, error)
	UnassignGroupRoles(ctx context.Context, a iam.Actor, group iam.GroupRef, subjects []iam.Subject, role iam.Role) ([]iam.OpResult, error)
	RemoveGroupMembers(ctx context.Context, a iam.Actor, group iam.GroupRef, subjects []iam.Subject) ([]iam.OpResult, error)
	GroupRoles(ctx context.Context, group iam.GroupRef, subjects []iam.Subject) (map[iam.Subject]iam.Role, error)
	CreateInstanceForSubject(ctx context.Context, group iam.GroupRef, displayName, ownerUserID string) (authflow.CreateInstanceResult, error)
	DefineGroupCustomRole(ctx context.Context, actorUserID string, group iam.GroupRef, def authflow.CustomRoleDef) error
	DeleteGroupCustomRole(ctx context.Context, actorUserID string, group iam.GroupRef, role iam.Role) error
	GroupNamingState(ctx context.Context, id string) (iam.NamingState, error)
	PermissionGroupSchema() *rbac.Schema
	UpdateGroupInstanceAs(ctx context.Context, actorUserID, groupID string, update iam.GroupInstanceUpdate) (iam.GroupInstance, error)
}
