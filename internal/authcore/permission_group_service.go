package authcore

// Service-level permission-group API (#111): the consumer entry points that wrap
// the store with the declared GroupSchema (catalog + containment validation),
// owner seeding, and transaction scoping. Group ids stay INTERNAL — callers
// address groups by (persona, instance_slug).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	authkit "github.com/open-rails/authkit"
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
	if err := s.groupStore().SeedContainment(ctx, s.groupSchemaOrDefault()); err != nil {
		return err
	}
	if report, err := s.RBACDriftReport(ctx); err == nil && report.Total() > 0 {
		slog.Default().Warn("authkit: rbac drift detected",
			"group_user_roles", report.GroupUserRoles,
			"group_custom_roles", report.CustomRoles,
			"api_keys", report.APIKeys,
		)
	}
	return nil
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
	return st.CreateGroup(ctx, RootPersona, "", "")
}

// CreatePermissionGroupRequest creates a permission group. Parent is addressed by
// (ParentPersona, ParentInstanceSlug); for a single-allowed-parent persona ParentPersona
// may be omitted. OwnerSubjectID, when set, is seeded with the owner role.
type CreatePermissionGroupRequest = authkit.CreatePermissionGroupRequest

// CreatePermissionGroup validates containment against the schema, resolves the
// parent group, creates the group, and (atomically) seeds the owner assignment.
// Returns the INTERNAL group id (for the caller's own bookkeeping; never exposed
// over the wire).
func (s *Service) CreatePermissionGroup(ctx context.Context, req CreatePermissionGroupRequest) (string, error) {
	sch := s.groupSchemaOrDefault()
	req.Persona = strings.TrimSpace(req.Persona)
	req.InstanceSlug = strings.TrimSpace(req.InstanceSlug)
	req.ParentPersona = strings.TrimSpace(req.ParentPersona)
	req.ParentInstanceSlug = strings.TrimSpace(req.ParentInstanceSlug)
	td, ok := sch.Persona(req.Persona)
	if !ok {
		return "", fmt.Errorf("unknown group persona %q: %w", req.Persona, authkit.ErrUnknownGroupPersona)
	}
	if err := validateGroupInstanceSlug(req.Persona, req.InstanceSlug); err != nil {
		return "", err
	}
	parentPersona := req.ParentPersona
	if req.Persona != RootPersona && parentPersona == "" && td.Parent != "" {
		parentPersona = td.Parent
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
			if err := validateGroupInstanceSlug(parentPersona, req.ParentInstanceSlug); err != nil {
				return "", err
			}
			parentID, err = st.GroupByInstanceSlug(ctx, parentPersona, req.ParentInstanceSlug)
		}
		if err != nil {
			return "", fmt.Errorf("resolve %q parent: %w", parentPersona, err)
		}
	}
	id, err := st.CreateGroup(ctx, req.Persona, parentID, req.InstanceSlug)
	if err != nil {
		return "", err
	}
	if req.OwnerSubjectID != "" {
		if err := s.requireMFAForRoleAssignment(ctx, db.ForSchema(tx, s.dbSchema()), id, req.Persona, req.OwnerSubjectID, SubjectKindUser, OwnerRoleName); err != nil {
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

// resolveGroupID maps (persona, instance_slug) to an internal id; the root persona is
// the singleton and ignores instance_slug.
func (s *Service) resolveGroupID(ctx context.Context, st *PermissionGroupStore, persona, instanceSlug string) (string, error) {
	persona = strings.TrimSpace(persona)
	instanceSlug = strings.TrimSpace(instanceSlug)
	if persona == RootPersona {
		return st.RootGroupID(ctx)
	}
	if err := validateGroupInstanceSlug(persona, instanceSlug); err != nil {
		return "", err
	}
	return st.GroupByInstanceSlug(ctx, persona, instanceSlug)
}

// ResolveGroupIDForSlug maps the API addressing key (persona, instanceSlug) to
// the group's INTERNAL id. The id never goes on the wire — this is for callers
// that must thread the controlling permission_group_id into a sibling resource
// (e.g. a remote_application's permission_group_id, #111). ErrGroupNotFound if
// no live group matches.
func (s *Service) ResolveGroupIDForSlug(ctx context.Context, persona, instanceSlug string) (string, error) {
	if err := s.requirePG(); err != nil {
		return "", err
	}
	return s.resolveGroupID(ctx, s.groupStore(), persona, instanceSlug)
}

// validRoleForPersona reports whether role is assignable in a group of persona: a
// catalog role, or any role when the persona allows custom roles (custom roles are
// validated at definition time).
func (s *Service) validRoleForPersona(sch *GroupSchema, persona, role string) bool {
	role = strings.TrimSpace(role)
	if role == "" {
		return false
	}
	if _, ok := sch.Role(persona, role); ok {
		return true
	}
	td, ok := sch.Persona(persona)
	return ok && td.Capabilities.CustomRoles
}

// AssignGroupRole grants a subject a role in the group addressed by (persona,
// instanceSlug). The role must be a catalog role (or any role for custom-enabled
// types). Gated by the MFA-required-role rule (#148/root-owner-MFA); genesis
// callers that must run before any policy can apply use AssignGroupRoleGenesis.
func (s *Service) AssignGroupRole(ctx context.Context, persona, instanceSlug, subjectID, subjectKind, role string) error {
	return s.assignGroupRole(ctx, persona, instanceSlug, subjectID, subjectKind, role, true)
}

// AssignGroupRoleGenesis grants a role with NEITHER actor-authz (#136) NOR the
// MFA-required-role gate (#148/root-owner-MFA). Reserved for genesis/bootstrap
// callers (GenesisClient, the bootstrap manifest) — the deploy-time trust root
// that runs before any actor-authorized request path (or any chance to enroll
// MFA) exists, so no runtime policy can apply yet. Never call this from a
// runtime request handler; use AssignGroupRole or AssignGroupRoleAs there.
func (s *Service) AssignGroupRoleGenesis(ctx context.Context, persona, instanceSlug, subjectID, subjectKind, role string) error {
	return s.assignGroupRole(ctx, persona, instanceSlug, subjectID, subjectKind, role, false)
}

func (s *Service) assignGroupRole(ctx context.Context, persona, instanceSlug, subjectID, subjectKind, role string, checkMFA bool) error {
	sch := s.groupSchemaOrDefault()
	if !s.validRoleForPersona(sch, persona, role) {
		return fmt.Errorf("role %q is not assignable in a %q group: %w", role, persona, ErrRoleNotAssignable)
	}
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, persona, instanceSlug)
	if err != nil {
		return err
	}
	if checkMFA {
		if err := s.requireMFAForRoleAssignment(ctx, db.ForSchema(s.pg, s.dbSchema()), gid, persona, subjectID, subjectKind, role); err != nil {
			return err
		}
	}
	return st.AssignRole(ctx, gid, subjectID, subjectKind, role)
}

// UnassignGroupRole revokes a subject's role in a group.
func (s *Service) UnassignGroupRole(ctx context.Context, persona, instanceSlug, subjectID, subjectKind, role string) error {
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, persona, instanceSlug)
	if err != nil {
		return err
	}
	return st.UnassignRole(ctx, gid, subjectID, subjectKind, role)
}

// RemoveGroupSubject revokes every role a subject holds in a group.
func (s *Service) RemoveGroupSubject(ctx context.Context, persona, instanceSlug, subjectID, subjectKind string) error {
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, persona, instanceSlug)
	if err != nil {
		return err
	}
	return st.UnassignSubject(ctx, gid, subjectID, subjectKind)
}

// Can is the Service-level authorization check: resolve the group addressed by
// (persona, instanceSlug), then test perm coverage via the additive walk-up.
// The caller constructs perm per the two-persona rule (LT:RT:action).
func (s *Service) Can(ctx context.Context, subjectID, subjectKind, persona, instanceSlug, perm string) (bool, error) {
	sch := s.groupSchemaOrDefault()
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, persona, instanceSlug)
	if err != nil {
		if errors.Is(err, ErrGroupNotFound) {
			return false, nil // no such group ⇒ no authority
		}
		return false, err
	}
	return st.CanOnGroup(ctx, sch, subjectID, subjectKind, gid, perm)
}

// ListEffectivePermissions returns the subject's effective grant PATTERNS in the
// group addressed by (persona, instanceSlug) — the de-duplicated union of every
// perm its roles grant, with globs (e.g. `root:*`) returned VERBATIM. This is the
// read primitive behind a "what can I do here" introspection endpoint (#421): a
// client fetches it once and gates UI on the strings (glob-matching with the same
// authkit.PermMatches the server enforces with) instead of re-deriving authority
// from role slugs. Scoped per group instance BY DESIGN — perms are persona-
// namespaced, so a global union would be both large and meaningless. An unknown
// group ⇒ empty (no authority), not an error; real lookup failures propagate
// (fail-closed — never a partial set returned as if complete).
func (s *Service) ListEffectivePermissions(ctx context.Context, subjectID, subjectKind, persona, instanceSlug string) ([]string, error) {
	sch := s.groupSchemaOrDefault()
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, persona, instanceSlug)
	if err != nil {
		if errors.Is(err, ErrGroupNotFound) {
			return []string{}, nil
		}
		return nil, err
	}
	return st.GrantsOnGroup(ctx, sch, subjectID, subjectKind, gid)
}

// ListGroupMembers returns the role-assignments in the group addressed by
// (persona, instanceSlug).
func (s *Service) ListGroupMembers(ctx context.Context, persona, instanceSlug string) ([]GroupMember, error) {
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, persona, instanceSlug)
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
// (persona, instanceSlug), acting as actorUserID. Requires the persona to allow
// custom roles; every permission must be a valid grant pattern in that
// persona's namespace (namespace purity) and must not collide with a catalog
// role name. requiresMFA mirrors RoleDef.RequiresMFA for catalog roles (#247).
//
// #247 SECURITY: redefining an EXISTING custom role is a DEFERRED grant (a
// widened grant set) — and, for a narrowed one, a deferred revoke — to EVERY
// subject currently holding it, the same class of risk invite-minting already
// gates (AK2-AUTHZ-1). Without this check, a bounded admin holding
// <persona>:roles:manage (but not the role's own grants) could redefine a role
// someone else holds to the full catalog, instantly widening their OWN
// effective grants without ever passing AssignGroupRoleAs's no-escalation
// gate. The actor must hold roles:manage AND already cover every permission in
// BOTH the role's current grants (if it exists) and the requested ones.
func (s *Service) DefineGroupCustomRole(ctx context.Context, actorUserID, persona, instanceSlug, role string, permissions []string, requiresMFA bool) error {
	sch := s.groupSchemaOrDefault()
	td, ok := sch.Persona(persona)
	if !ok {
		return fmt.Errorf("unknown group persona %q: %w", persona, authkit.ErrUnknownGroupPersona)
	}
	if !td.Capabilities.CustomRoles {
		return fmt.Errorf("group persona %q does not allow custom roles: %w", persona, authkit.ErrCustomRolesNotSupported)
	}
	if !segmentRe.MatchString(role) {
		return fmt.Errorf("custom role name %q must match [a-z][a-z0-9-]*: %w", role, authkit.ErrCustomRoleNameInvalid)
	}
	if _, isCatalog := sch.Role(persona, role); isCatalog {
		return fmt.Errorf("role %q is a catalog role and cannot be redefined as custom: %w", role, authkit.ErrCustomRoleIsCatalogRole)
	}
	for _, p := range permissions {
		if err := ValidateGrantPattern(p); err != nil {
			return err
		}
		if PermissionPersona(p) != persona {
			return fmt.Errorf("custom role grant %q is cross-persona — a %q role may hold only %q: perms: %w", p, persona, persona, authkit.ErrCustomRoleGrantCrossPersona)
		}
	}
	universe, ok := sch.GrantableUniverse(persona)
	if !ok {
		return fmt.Errorf("unknown group persona %q: %w", persona, authkit.ErrUnknownGroupPersona)
	}
	allowed := make(map[string]struct{}, len(universe))
	for _, p := range universe {
		allowed[p] = struct{}{}
	}
	for _, p := range permissions {
		if _, ok := allowed[p]; !ok {
			return fmt.Errorf("custom role grant %q is outside catalog: %w", p, authkit.ErrCustomRoleGrantOutsideCatalog)
		}
	}
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, persona, instanceSlug)
	if err != nil {
		return err
	}
	oldGrants, _, err := st.CustomRole(ctx, gid, role)
	if err != nil {
		return err
	}
	if err := s.authorizeCustomRoleChange(ctx, st, sch, persona, gid, actorUserID, oldGrants, permissions); err != nil {
		return err
	}
	return st.UpsertCustomRole(ctx, gid, role, permissions, requiresMFA)
}

// DeleteGroupCustomRole removes a custom role from a group, acting as
// actorUserID. #247 SECURITY: deleting a role is a DEFERRED REVOKE from every
// subject currently holding it, gated by the same capability + no-escalation
// rule as DefineGroupCustomRole (covering the role's stored grants; a
// not-yet-defined role has nothing to revoke, so only the capability check
// applies).
func (s *Service) DeleteGroupCustomRole(ctx context.Context, actorUserID, persona, instanceSlug, role string) error {
	sch := s.groupSchemaOrDefault()
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, persona, instanceSlug)
	if err != nil {
		return err
	}
	oldGrants, _, err := st.CustomRole(ctx, gid, role)
	if err != nil {
		return err
	}
	if err := s.authorizeCustomRoleChange(ctx, st, sch, persona, gid, actorUserID, oldGrants, nil); err != nil {
		return err
	}
	return st.DeleteCustomRole(ctx, gid, role)
}
