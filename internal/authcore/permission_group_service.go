package authcore

// Service-level permission-group API (#111): the consumer entry points that wrap
// the store with the declared GroupSchema (catalog + containment validation),
// owner seeding, and transaction scoping. Group ids stay INTERNAL — callers
// address groups by (persona, resource_slug).

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
// group_persona_parents so the DB trigger can enforce tree shape. Idempotent; call
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
	return st.CreateGroup(ctx, RootPersona, "", "", "")
}

// CreatePermissionGroupRequest creates a permission group. Parent is addressed by
// (ParentPersona, ParentResourceSlug); for a single-allowed-parent persona ParentPersona
// may be omitted. OwnerSubjectID, when set, is seeded with the owner role.
type CreatePermissionGroupRequest struct {
	Persona            string
	ResourceSlug       string
	ParentPersona      string
	ParentResourceSlug string
	OwnerSubjectID     string
}

// CreatePermissionGroup validates containment against the schema, resolves the
// parent group, creates the group, and (atomically) seeds the owner assignment.
// Returns the INTERNAL group id (for the caller's own bookkeeping; never exposed
// over the wire).
func (s *Service) CreatePermissionGroup(ctx context.Context, req CreatePermissionGroupRequest) (string, error) {
	sch := s.groupSchemaOrDefault()
	req.Persona = strings.TrimSpace(req.Persona)
	req.ResourceSlug = strings.TrimSpace(req.ResourceSlug)
	req.ParentPersona = strings.TrimSpace(req.ParentPersona)
	req.ParentResourceSlug = strings.TrimSpace(req.ParentResourceSlug)
	td, ok := sch.Persona(req.Persona)
	if !ok {
		return "", fmt.Errorf("unknown group persona %q", req.Persona)
	}
	if err := validateGroupResourceSlug(req.Persona, req.ResourceSlug); err != nil {
		return "", err
	}
	parentPersona := req.ParentPersona
	if req.Persona != RootPersona && parentPersona == "" && len(td.AllowedParents) == 1 {
		parentPersona = td.AllowedParents[0] // unambiguous
	}
	if err := sch.ValidateParent(req.Persona, parentPersona); err != nil {
		return "", err
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := NewPermissionGroupStore(db.ForSchema(tx, s.dbSchema()))

	parentID := ""
	if req.Persona != RootPersona {
		if parentPersona == RootPersona {
			parentID, err = st.RootGroupID(ctx)
		} else {
			if err := validateGroupResourceSlug(parentPersona, req.ParentResourceSlug); err != nil {
				return "", err
			}
			parentID, err = st.GroupByResourceSlug(ctx, parentPersona, req.ParentResourceSlug)
		}
		if err != nil {
			return "", fmt.Errorf("resolve %q parent: %w", parentPersona, err)
		}
	}
	id, err := st.CreateGroup(ctx, req.Persona, parentID, parentPersona, req.ResourceSlug)
	if err != nil {
		return "", err
	}
	if req.OwnerSubjectID != "" {
		if err := s.requireMFAForRoleAssignment(ctx, db.ForSchema(tx, s.dbSchema()), req.Persona, req.OwnerSubjectID, SubjectKindUser, OwnerRoleName); err != nil {
			return "", fmt.Errorf("seed owner: %w", err)
		}
		if err := st.AssignRole(ctx, id, req.OwnerSubjectID, SubjectKindUser, OwnerRoleName); err != nil {
			return "", fmt.Errorf("seed owner: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return id, nil
}

// resolveGroupID maps (persona, resource_slug) to an internal id; the root persona is
// the singleton and ignores resource_slug.
func (s *Service) resolveGroupID(ctx context.Context, st *PermissionGroupStore, persona, resourceSlug string) (string, error) {
	persona = strings.TrimSpace(persona)
	resourceSlug = strings.TrimSpace(resourceSlug)
	if persona == RootPersona {
		return st.RootGroupID(ctx)
	}
	if err := validateGroupResourceSlug(persona, resourceSlug); err != nil {
		return "", err
	}
	return st.GroupByResourceSlug(ctx, persona, resourceSlug)
}

// ResolveGroupIDForSlug maps the API addressing key (persona, resourceSlug) to
// the group's INTERNAL id. The id never goes on the wire — this is for callers
// that must thread the controlling permission_group_id into a sibling resource
// (e.g. a remote_application's permission_group_id, #111). ErrGroupNotFound if
// no live group matches.
func (s *Service) ResolveGroupIDForSlug(ctx context.Context, persona, resourceSlug string) (string, error) {
	if err := s.requirePG(); err != nil {
		return "", err
	}
	return s.resolveGroupID(ctx, s.groupStore(), persona, resourceSlug)
}

// validRoleForPersona reports whether role is assignable in a group of persona: a
// catalog role, or any role when the persona allows custom roles (custom roles are
// validated at definition time).
func (s *Service) validRoleForPersona(sch *GroupSchema, persona, role string) bool {
	if _, ok := sch.Role(persona, role); ok {
		return true
	}
	td, ok := sch.Persona(persona)
	return ok && td.AllowCustomRoles
}

// AssignGroupRole grants a subject a role in the group addressed by (persona,
// resourceSlug). The role must be a catalog role (or any role for custom-enabled
// types).
func (s *Service) AssignGroupRole(ctx context.Context, persona, resourceSlug, subjectID, subjectKind, role string) error {
	sch := s.groupSchemaOrDefault()
	if !s.validRoleForPersona(sch, persona, role) {
		return fmt.Errorf("role %q is not assignable in a %q group", role, persona)
	}
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, persona, resourceSlug)
	if err != nil {
		return err
	}
	if err := s.requireMFAForRoleAssignment(ctx, db.ForSchema(s.pg, s.dbSchema()), persona, subjectID, subjectKind, role); err != nil {
		return err
	}
	return st.AssignRole(ctx, gid, subjectID, subjectKind, role)
}

// UnassignGroupRole revokes a subject's role in a group.
func (s *Service) UnassignGroupRole(ctx context.Context, persona, resourceSlug, subjectID, subjectKind, role string) error {
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, persona, resourceSlug)
	if err != nil {
		return err
	}
	return st.UnassignRole(ctx, gid, subjectID, subjectKind, role)
}

// RemoveGroupSubject revokes every role a subject holds in a group.
func (s *Service) RemoveGroupSubject(ctx context.Context, persona, resourceSlug, subjectID, subjectKind string) error {
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, persona, resourceSlug)
	if err != nil {
		return err
	}
	return st.UnassignSubject(ctx, gid, subjectID, subjectKind)
}

// Can is the Service-level authorization check: resolve the group addressed by
// (persona, resourceSlug), then test perm coverage via the additive walk-up.
// The caller constructs perm per the two-persona rule (LT:RT:action).
func (s *Service) Can(ctx context.Context, subjectID, subjectKind, persona, resourceSlug, perm string) (bool, error) {
	sch := s.groupSchemaOrDefault()
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, persona, resourceSlug)
	if err != nil {
		if errors.Is(err, ErrGroupNotFound) {
			return false, nil // no such group ⇒ no authority
		}
		return false, err
	}
	return st.CanOnGroup(ctx, sch, subjectID, subjectKind, gid, perm)
}

// ListGroupMembers returns the role-assignments in the group addressed by
// (persona, resourceSlug).
func (s *Service) ListGroupMembers(ctx context.Context, persona, resourceSlug string) ([]GroupMember, error) {
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, persona, resourceSlug)
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
// (persona, resourceSlug). Requires the persona to allow custom roles; every
// permission must be a valid grant pattern in that persona's namespace
// (namespace purity) and must not collide with a catalog role name.
func (s *Service) DefineGroupCustomRole(ctx context.Context, persona, resourceSlug, role string, permissions []string) error {
	sch := s.groupSchemaOrDefault()
	td, ok := sch.Persona(persona)
	if !ok {
		return fmt.Errorf("unknown group persona %q", persona)
	}
	if !td.AllowCustomRoles {
		return fmt.Errorf("group persona %q does not allow custom roles", persona)
	}
	if !segmentRe.MatchString(role) {
		return fmt.Errorf("custom role name %q must match [a-z][a-z0-9-]*", role)
	}
	if _, isCatalog := sch.Role(persona, role); isCatalog {
		return fmt.Errorf("role %q is a catalog role and cannot be redefined as custom", role)
	}
	for _, p := range permissions {
		if err := ValidateGrantPattern(p); err != nil {
			return err
		}
		if PermissionPersona(p) != persona {
			return fmt.Errorf("custom role grant %q is cross-persona — a %q role may hold only %q: perms", p, persona, persona)
		}
	}
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, persona, resourceSlug)
	if err != nil {
		return err
	}
	return st.UpsertCustomRole(ctx, gid, role, permissions)
}

// DeleteGroupCustomRole removes a custom role from a group.
func (s *Service) DeleteGroupCustomRole(ctx context.Context, persona, resourceSlug, role string) error {
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, persona, resourceSlug)
	if err != nil {
		return err
	}
	return st.DeleteCustomRole(ctx, gid, role)
}
