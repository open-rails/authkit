package core

// Service-level permission-group API (#111): the consumer entry points that wrap
// the store with the declared GroupSchema (catalog + containment validation),
// owner seeding, and transaction scoping. Group ids stay INTERNAL — callers
// address groups by (type, resource_ref).

import (
	"context"
	"errors"
	"fmt"

	"github.com/open-rails/authkit/internal/db"
)

// PermissionGroupSchema returns the validated schema this Service was built with
// (the intrinsic root-only schema if constructed without Config groups).
func (s *Service) PermissionGroupSchema() *GroupSchema {
	return s.groupSchemaOrDefault()
}

func (s *Service) groupSchemaOrDefault() *GroupSchema {
	if s.groupSchema != nil {
		return s.groupSchema
	}
	gs, _ := BuildSchema() // root-only; cannot fail
	return gs
}

// groupStore binds a PermissionGroupStore to the Service's schema-rewriting pool
// handle (so "profiles." resolves to the configured schema, authkit #69).
func (s *Service) groupStore() *PermissionGroupStore {
	return NewPermissionGroupStore(db.ForSchema(s.pg, s.dbSchema()))
}

// SeedPermissionGroupContainment writes the declared containment schema into
// group_type_parents so the DB trigger can enforce tree shape. Idempotent; call
// once at bootstrap.
func (s *Service) SeedPermissionGroupContainment(ctx context.Context) error {
	return s.groupStore().SeedContainment(ctx, s.groupSchemaOrDefault())
}

// EnsureRootGroup creates the singleton root group if absent (idempotent) and
// returns its internal id.
func (s *Service) EnsureRootGroup(ctx context.Context) (string, error) {
	st := s.groupStore()
	id, err := st.RootGroupID(ctx)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, ErrGroupNotFound) {
		return "", err
	}
	return st.CreateGroup(ctx, RootType, "", "", "")
}

// CreatePermissionGroupRequest creates a typed group. Parent is addressed by
// (ParentType, ParentResourceRef); for a single-allowed-parent type ParentType
// may be omitted. OwnerSubjectID, when set, is seeded with the owner role.
type CreatePermissionGroupRequest struct {
	Type              string
	ResourceRef       string
	ParentType        string
	ParentResourceRef string
	OwnerSubjectID    string
}

// CreatePermissionGroup validates containment against the schema, resolves the
// parent group, creates the group, and (atomically) seeds the owner assignment.
// Returns the INTERNAL group id (for the caller's own bookkeeping; never exposed
// over the wire).
func (s *Service) CreatePermissionGroup(ctx context.Context, req CreatePermissionGroupRequest) (string, error) {
	sch := s.groupSchemaOrDefault()
	td, ok := sch.Type(req.Type)
	if !ok {
		return "", fmt.Errorf("unknown group type %q", req.Type)
	}
	parentType := req.ParentType
	if req.Type != RootType && parentType == "" && len(td.AllowedParents) == 1 {
		parentType = td.AllowedParents[0] // unambiguous
	}
	if err := sch.ValidateParent(req.Type, parentType); err != nil {
		return "", err
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := NewPermissionGroupStore(db.ForSchema(tx, s.dbSchema()))

	parentID := ""
	if req.Type != RootType {
		if parentType == RootType {
			parentID, err = st.RootGroupID(ctx)
		} else {
			parentID, err = st.GroupByResourceRef(ctx, parentType, req.ParentResourceRef)
		}
		if err != nil {
			return "", fmt.Errorf("resolve %q parent: %w", parentType, err)
		}
	}
	id, err := st.CreateGroup(ctx, req.Type, parentID, parentType, req.ResourceRef)
	if err != nil {
		return "", err
	}
	if req.OwnerSubjectID != "" {
		if err := st.AssignRole(ctx, id, req.OwnerSubjectID, SubjectKindUser, OwnerRoleName); err != nil {
			return "", fmt.Errorf("seed owner: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return id, nil
}

// resolveGroupID maps (type, resource_ref) to an internal id; the root type is
// the singleton and ignores resource_ref.
func (s *Service) resolveGroupID(ctx context.Context, st *PermissionGroupStore, groupType, resourceRef string) (string, error) {
	if groupType == RootType {
		return st.RootGroupID(ctx)
	}
	return st.GroupByResourceRef(ctx, groupType, resourceRef)
}

// ResolveGroupIDForRef maps the API addressing key (groupType, resourceRef) to
// the group's INTERNAL id. The id never goes on the wire — this is for callers
// that must thread the controlling permission_group_id into a sibling resource
// (e.g. a remote_application's permission_group_id, #111). ErrGroupNotFound if
// no live group matches.
func (s *Service) ResolveGroupIDForRef(ctx context.Context, groupType, resourceRef string) (string, error) {
	if err := s.requirePG(); err != nil {
		return "", err
	}
	return s.resolveGroupID(ctx, s.groupStore(), groupType, resourceRef)
}

// validRoleForType reports whether role is assignable in a group of groupType: a
// catalog role, or any role when the type allows custom roles (custom roles are
// validated at definition time).
func (s *Service) validRoleForType(sch *GroupSchema, groupType, role string) bool {
	if _, ok := sch.Role(groupType, role); ok {
		return true
	}
	td, ok := sch.Type(groupType)
	return ok && td.AllowCustomRoles
}

// AssignGroupRole grants a subject a role in the group addressed by (groupType,
// resourceRef). The role must be a catalog role (or any role for custom-enabled
// types).
func (s *Service) AssignGroupRole(ctx context.Context, groupType, resourceRef, subjectID, subjectKind, role string) error {
	sch := s.groupSchemaOrDefault()
	if !s.validRoleForType(sch, groupType, role) {
		return fmt.Errorf("role %q is not assignable in a %q group", role, groupType)
	}
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, groupType, resourceRef)
	if err != nil {
		return err
	}
	return st.AssignRole(ctx, gid, subjectID, subjectKind, role)
}

// UnassignGroupRole revokes a subject's role in a group.
func (s *Service) UnassignGroupRole(ctx context.Context, groupType, resourceRef, subjectID, subjectKind, role string) error {
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, groupType, resourceRef)
	if err != nil {
		return err
	}
	return st.UnassignRole(ctx, gid, subjectID, subjectKind, role)
}

// Can is the Service-level authorization check: resolve the group addressed by
// (groupType, resourceRef), then test perm coverage via the additive walk-up.
// The caller constructs perm per the two-persona rule (LT:RT:action).
func (s *Service) Can(ctx context.Context, subjectID, subjectKind, groupType, resourceRef, perm string) (bool, error) {
	sch := s.groupSchemaOrDefault()
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, groupType, resourceRef)
	if err != nil {
		if errors.Is(err, ErrGroupNotFound) {
			return false, nil // no such group ⇒ no authority
		}
		return false, err
	}
	return st.CanOnGroup(ctx, sch, subjectID, subjectKind, gid, perm)
}

// ListGroupMembers returns the role-assignments in the group addressed by
// (groupType, resourceRef).
func (s *Service) ListGroupMembers(ctx context.Context, groupType, resourceRef string) ([]GroupMember, error) {
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, groupType, resourceRef)
	if err != nil {
		return nil, err
	}
	return st.GroupMembers(ctx, gid)
}

// ListSubjectGroups returns every group membership a subject holds (the
// cross-persona discovery behind /me/groups).
func (s *Service) ListSubjectGroups(ctx context.Context, subjectID, subjectKind string) ([]SubjectGroupMembership, error) {
	return s.groupStore().SubjectGroups(ctx, subjectID, subjectKind)
}

// DefineGroupCustomRole creates/updates a custom role in the group addressed by
// (groupType, resourceRef). Requires the type to allow custom roles; every
// permission must be a valid grant pattern in the type's OWN persona namespace
// (namespace purity) and must not collide with a catalog role name.
func (s *Service) DefineGroupCustomRole(ctx context.Context, groupType, resourceRef, role string, permissions []string) error {
	sch := s.groupSchemaOrDefault()
	td, ok := sch.Type(groupType)
	if !ok {
		return fmt.Errorf("unknown group type %q", groupType)
	}
	if !td.AllowCustomRoles {
		return fmt.Errorf("group type %q does not allow custom roles", groupType)
	}
	if !segmentRe.MatchString(role) {
		return fmt.Errorf("custom role name %q must match [a-z][a-z0-9-]*", role)
	}
	if _, isCatalog := sch.Role(groupType, role); isCatalog {
		return fmt.Errorf("role %q is a catalog role and cannot be redefined as custom", role)
	}
	for _, p := range permissions {
		if err := ValidateGrantPattern(p); err != nil {
			return err
		}
		if PermissionPersona(p) != groupType {
			return fmt.Errorf("custom role grant %q is cross-persona — a %q role may hold only %q: perms", p, groupType, groupType)
		}
	}
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, groupType, resourceRef)
	if err != nil {
		return err
	}
	return st.UpsertCustomRole(ctx, gid, role, permissions)
}

// DeleteGroupCustomRole removes a custom role from a group.
func (s *Service) DeleteGroupCustomRole(ctx context.Context, groupType, resourceRef, role string) error {
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, groupType, resourceRef)
	if err != nil {
		return err
	}
	return st.DeleteCustomRole(ctx, gid, role)
}
