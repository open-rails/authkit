package httpapi

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/rbac"
)

// groupsBackend is permission groups, roles and permission checks.
type groupsBackend interface {
	Can(ctx context.Context, a iam.Actor, ref iam.GroupRef, perm iam.Perm) (bool, error)
	EffectivePermissions(ctx context.Context, a iam.Actor, refs []iam.GroupRef) (map[string][]iam.Perm, error)
	Group(ctx context.Context, ref iam.GroupRef) (iam.Group, error)
	ListGroupMembers(ctx context.Context, ref iam.GroupRef, q iam.MemberQuery) (iam.ListPage[iam.GroupMember], error)
	ListSubjectGroups(ctx context.Context, s iam.Subject, p iam.PageRequest) (iam.ListPage[iam.Membership], error)
	AssignGroupRoles(ctx context.Context, a iam.Actor, group iam.GroupRef, subjects []iam.Subject, role iam.Role) ([]iam.OpResult, error)
	UnassignGroupRoles(ctx context.Context, a iam.Actor, group iam.GroupRef, subjects []iam.Subject, role iam.Role) ([]iam.OpResult, error)
	RemoveGroupMembers(ctx context.Context, a iam.Actor, group iam.GroupRef, subjects []iam.Subject) ([]iam.OpResult, error)
	DefineGroupRole(ctx context.Context, a iam.Actor, ref iam.GroupRef, r iam.CustomRole) error
	DeleteGroupRole(ctx context.Context, a iam.Actor, ref iam.GroupRef, role iam.Role) error
	PermissionGroupSchema() *rbac.Schema
}
