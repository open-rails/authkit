package embedded

// Client-level permission-group API (#111): the consumer entry points that wrap
// the store with the declared GroupSchema (catalog + containment validation),
// owner seeding, and transaction scoping. Group ids stay INTERNAL — callers
// address groups by (persona, instance_slug).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

// PermissionGroupSchema returns the validated schema this Client was built with
// (the intrinsic root-only schema if constructed without Config groups).
func (s *Client) PermissionGroupSchema() *GroupSchema {
	return s.groupSchemaOrDefault()
}

func (s *Client) groupSchemaOrDefault() *GroupSchema {
	if s.groupSchema != nil {
		return s.groupSchema
	}
	gs, _ := BuildSchema() // root-only; cannot fail
	return gs
}

// groupStore binds a PermissionGroupStore to the Client's schema-rewriting pool
// handle (so "profiles." resolves to the configured schema, authkit #69).
func (s *Client) groupStore() *PermissionGroupStore {
	return s.groupStoreFor(db.ForSchema(s.pg, s.dbSchema()))
}

// SeedPermissionGroupContainment writes the declared containment schema into
// group_persona_parents so the DB trigger can enforce tree shape. Idempotent; call
// once at bootstrap.
func (s *Client) SeedPermissionGroupContainment(ctx context.Context) error {
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
// returns its internal id. Concurrent cold boots race the singleton index; the
// loser adopts the winner's row instead of failing (#258).
func (s *Client) EnsureRootGroup(ctx context.Context) (string, error) {
	st := s.groupStore()
	id, err := st.RootGroupID(ctx)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, ErrGroupNotFound) {
		return "", err
	}
	id, createErr := st.CreateGroup(ctx, authkit.RootGroup(), "")
	if createErr == nil {
		return id, nil
	}
	if id, err := st.RootGroupID(ctx); err == nil {
		return id, nil
	}
	return "", createErr
}

// CreatePermissionGroupRequest creates a permission group. Parent is addressed by
// (ParentPersona, ParentInstanceSlug); for a single-allowed-parent persona ParentPersona
// may be omitted. OwnerSubjectID, when set, is seeded with the owner role.
type CreatePermissionGroupRequest = authkit.CreatePermissionGroupRequest

// CreatePermissionGroup validates containment against the schema, resolves the
// parent group, creates the group, and (atomically) seeds the owner assignment.
// Returns the INTERNAL group id (for the caller's own bookkeeping; never exposed
// over the wire).
func (s *Client) CreatePermissionGroup(ctx context.Context, req CreatePermissionGroupRequest) (string, error) {
	sch := s.groupSchemaOrDefault()
	req.Persona = authkit.Persona(strings.TrimSpace(string(req.Persona)))
	req.InstanceSlug = strings.TrimSpace(req.InstanceSlug)
	req.ParentPersona = authkit.Persona(strings.TrimSpace(string(req.ParentPersona)))
	req.ParentInstanceSlug = strings.TrimSpace(req.ParentInstanceSlug)
	group := authkit.GroupRef{Persona: req.Persona, Instance: req.InstanceSlug}
	td, ok := sch.Persona(req.Persona)
	if !ok {
		return "", fmt.Errorf("unknown group persona %q: %w", req.Persona, authkit.ErrUnknownGroupPersona)
	}
	if err := validateGroupInstanceSlug(group); err != nil {
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
	st := s.groupStoreFor(db.ForSchema(tx, s.dbSchema()))

	parentID := ""
	if req.Persona != RootPersona {
		if parentPersona == RootPersona {
			parentID, err = st.RootGroupID(ctx)
		} else {
			parent := authkit.GroupRef{Persona: parentPersona, Instance: req.ParentInstanceSlug}
			if err := validateGroupInstanceSlug(parent); err != nil {
				return "", err
			}
			parentID, err = st.GroupByInstanceSlug(ctx, parent)
		}
		if err != nil {
			return "", fmt.Errorf("resolve %q parent: %w", parentPersona, err)
		}
	}
	id, err := st.CreateGroupNamed(ctx, group, parentID, strings.TrimSpace(req.DisplayName))
	if err != nil {
		return "", err
	}
	if req.OwnerSubjectID != "" {
		// #264 service-owned orgs: the owner may be a user (default) or a
		// remote-application principal.
		owner := authkit.Subject{ID: req.OwnerSubjectID, Kind: req.OwnerSubjectKind}
		if owner.Kind == "" {
			owner.Kind = SubjectKindUser
		}
		if _, _, err := groupRoleTable(owner.Kind); err != nil {
			return "", err
		}
		if err := s.requireMFAForRoleAssignment(ctx, db.ForSchema(tx, s.dbSchema()), id, req.Persona, owner, OwnerRoleName); err != nil {
			return "", fmt.Errorf("seed owner: %w", err)
		}
		if err := st.AssignRole(ctx, id, owner, OwnerRoleName); err != nil {
			return "", fmt.Errorf("seed owner: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return id, nil
}

// SetPermissionGroupDisplayName updates a group's free-form, non-unique
// display name (#264 naming doctrine: vanity naming lives here, renameable at
// will; the slug stays the unique handle). Callers gate authorization.
func (s *Client) SetPermissionGroupDisplayName(ctx context.Context, group authkit.GroupRef, displayName string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, group)
	if err != nil {
		return err
	}
	return st.SetGroupDisplayName(ctx, gid, truncateDisplayName(displayName))
}

// UpdateGroupInstanceAs applies settings to one captured UUID. It authorizes
// before even a no-op and never resolves a mutable spelling after authorization.
func (s *Client) UpdateGroupInstanceAs(ctx context.Context, actorUserID, groupID string, update authkit.GroupInstanceUpdate) (authkit.GroupInstance, error) {
	var out authkit.GroupInstance
	if err := s.requirePG(); err != nil {
		return out, err
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.groupStoreFor(db.ForSchema(tx, s.dbSchema()))
	var persona authkit.Persona
	var current string
	if err := st.q.QueryRow(ctx, `SELECT persona,COALESCE(instance_slug,'') FROM profiles.permission_groups WHERE id=$1::uuid FOR UPDATE`, groupID).Scan(&persona, &current); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return out, ErrGroupNotFound
		}
		return out, err
	}
	allowed, err := st.CanOnGroup(ctx, s.groupSchemaOrDefault(), authkit.UserSubject(actorUserID), groupID, PermSettingsManage(persona))
	if err != nil {
		return out, err
	}
	if !allowed {
		return out, authkit.ErrInsufficientRoleAuthority
	}
	if update.Slug != nil {
		newSlug := strings.ToLower(strings.TrimSpace(*update.Slug))
		if persona == RootPersona {
			return out, authkit.ErrUnknownGroupPersona
		}
		if newSlug != current {
			if err := s.authorizeSlugClaim(ctx, s.groupSchemaOrDefault(), authkit.GroupRef{Persona: persona, Instance: newSlug}, actorUserID); err != nil {
				return out, err
			}
			var managed bool
			if err := st.q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM profiles.remote_applications WHERE permission_group_id=$1::uuid AND trust_root='domain')`, groupID).Scan(&managed); err != nil {
				return out, err
			}
			if managed {
				return out, ErrGroupSlugApplicationManaged
			}
			if err := s.admitName(ctx, authkit.NameAdmissionRequest{OwnerKind: "group", Persona: persona, OwnerID: groupID, ActorID: actorUserID, CurrentName: current, RequestedName: newSlug, Operation: authkit.NameRename}); err != nil {
				return out, err
			}
			if err := st.renameGroupSlug(ctx, groupID, newSlug, s.NamingPolicy()); err != nil {
				return out, err
			}
		}
	}
	if update.DisplayName != nil {
		if len(*update.DisplayName) > 256 {
			return out, authkit.ErrGroupSlugInvalid
		}
		if err := st.SetGroupDisplayName(ctx, groupID, strings.TrimSpace(*update.DisplayName)); err != nil {
			return out, err
		}
	}
	out, err = st.GroupInstanceByID(ctx, groupID)
	if err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}

// resolveGroupID maps (persona, instance_slug) to an internal id; the root persona is
// the singleton and ignores instance_slug.
func (s *Client) resolveGroupID(ctx context.Context, st *PermissionGroupStore, g authkit.GroupRef) (string, error) {
	g.Persona = authkit.Persona(strings.TrimSpace(string(g.Persona)))
	g.Instance = strings.TrimSpace(g.Instance)
	if g.IsRoot() {
		return st.RootGroupID(ctx)
	}
	if err := validateGroupInstanceSlug(g); err != nil {
		return "", err
	}
	return st.GroupByInstanceSlug(ctx, g)
}

// ResolveGroupIDForSlug maps the API addressing key (persona, instanceSlug) to
// the group's INTERNAL id, for IN-PROCESS callers that must thread the
// controlling permission_group_id into a sibling resource (e.g. a
// remote_application's permission_group_id, #111). ErrGroupNotFound if no live
// group matches. Out-of-process callers use GroupInstanceForSlug, which the
// HTTP descriptor route exposes under an authorization gate (#269).
func (s *Client) ResolveGroupIDForSlug(ctx context.Context, group authkit.GroupRef) (string, error) {
	if err := s.requirePG(); err != nil {
		return "", err
	}
	return s.resolveGroupID(ctx, s.groupStore(), group)
}

// GroupInstanceForSlug reads one instance's own identity — id, persona, slug,
// display name (#269). This is the read behind GET /<persona>/:instance_slug:
// the id is a JOIN KEY a host needs for its own ledger rows, never an address.
// Authorization is the caller's job (the route gates on <persona>:settings:read).
func (s *Client) GroupInstanceForSlug(ctx context.Context, group authkit.GroupRef) (GroupInstance, error) {
	if err := s.requirePG(); err != nil {
		return GroupInstance{}, err
	}
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, group)
	if err != nil {
		return GroupInstance{}, err
	}
	return st.GroupInstanceByID(ctx, gid)
}

// validRoleForPersona reports whether role is assignable in a group of persona: a
// catalog role, or any role when the persona allows custom roles (custom roles are
// validated at definition time).
func (s *Client) validRoleForPersona(sch *GroupSchema, persona authkit.Persona, role authkit.Role) bool {
	role = authkit.Role(strings.TrimSpace(string(role)))
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
func (s *Client) AssignGroupRole(ctx context.Context, group authkit.GroupRef, subject authkit.Subject, role authkit.Role) error {
	return s.assignGroupRole(ctx, group, subject, role, true)
}

// AssignGroupRoleGenesis grants a role with NEITHER actor-authz (#136) NOR the
// MFA-required-role gate (#148/root-owner-MFA). Reserved for genesis/bootstrap
// callers (GenesisClient, the bootstrap manifest) — the deploy-time trust root
// that runs before any actor-authorized request path (or any chance to enroll
// MFA) exists, so no runtime policy can apply yet. Never call this from a
// runtime request handler; use AssignGroupRole or AssignGroupRoleAs there.
func (s *Client) AssignGroupRoleGenesis(ctx context.Context, group authkit.GroupRef, subject authkit.Subject, role authkit.Role) error {
	return s.assignGroupRole(ctx, group, subject, role, false)
}

func (s *Client) assignGroupRole(ctx context.Context, group authkit.GroupRef, subject authkit.Subject, role authkit.Role, checkMFA bool) error {
	sch := s.groupSchemaOrDefault()
	if !s.validRoleForPersona(sch, group.Persona, role) {
		return fmt.Errorf("role %q is not assignable in a %q group: %w", role, group.Persona, ErrRoleNotAssignable)
	}
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, group)
	if err != nil {
		return err
	}
	if checkMFA {
		if err := s.requireMFAForRoleAssignment(ctx, db.ForSchema(s.pg, s.dbSchema()), gid, group.Persona, subject, role); err != nil {
			return err
		}
	}
	return st.AssignRole(ctx, gid, subject, role)
}

// UnassignGroupRole revokes a subject's role in a group.
func (s *Client) UnassignGroupRole(ctx context.Context, group authkit.GroupRef, subject authkit.Subject, role authkit.Role) error {
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, group)
	if err != nil {
		return err
	}
	return st.UnassignRole(ctx, gid, subject, role)
}

// DeletePermissionGroupOptions controls the delete-time naming rule (#264).
type DeletePermissionGroupOptions = authkit.DeletePermissionGroupOptions

// DeletePermissionGroup deletes a group instance (children, role assignments,
// api keys, and remote applications cascade). Delete-time naming rule (#264
// ruling 5): by DEFAULT the slug is TOMBSTONED to the group uuid forever —
// fail-safe, published references can never be re-claimed. Passing
// ReleaseSlug frees the name instead; that is safe ONLY for names nothing
// ever referenced, and the judgment is the host's. authkit itself never
// deletes a group — dormancy policy is entirely host-side.
func (s *Client) DeletePermissionGroup(ctx context.Context, group authkit.GroupRef, opts DeletePermissionGroupOptions) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	group.Persona = authkit.Persona(strings.TrimSpace(string(group.Persona)))
	group.Instance = strings.TrimSpace(group.Instance)
	if group.IsRoot() {
		return fmt.Errorf("the root group cannot be deleted: %w", authkit.ErrUnknownGroupPersona)
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.groupStoreFor(db.ForSchema(tx, s.dbSchema()))
	gid, bound, err := st.requestGroupID(ctx, group)
	if !bound {
		gid, err = st.GroupByLiveInstanceSlug(ctx, group)
	}
	if err != nil {
		return err
	}
	if err := st.DeleteGroup(ctx, gid, opts); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Can is the Client-level authorization check: resolve the group addressed by
// (persona, instanceSlug), then test perm coverage via the additive walk-up.
// The caller constructs perm per the two-persona rule (LT:RT:action).
func (s *Client) Can(ctx context.Context, subject authkit.Subject, group authkit.GroupRef, perm authkit.Perm) (bool, error) {
	sch := s.groupSchemaOrDefault()
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, group)
	if err != nil {
		if errors.Is(err, ErrGroupNotFound) {
			return false, nil // no such group ⇒ no authority
		}
		return false, err
	}
	return st.CanOnGroup(ctx, sch, subject, gid, perm)
}

// ListEffectivePermissions returns the subject's effective grant PATTERNS in the
// group addressed by (persona, instanceSlug) — the de-duplicated union of every
// perm its roles grant, with globs (e.g. `root:*`) returned VERBATIM. This is the
// read primitive behind a "what can I do here" introspection endpoint (#421): a
// client fetches it once and gates UI on the strings (glob-matching with the same
// authkit.Perm.Matches the server enforces with) instead of re-deriving authority
// from role slugs. Scoped per group instance BY DESIGN — perms are persona-
// namespaced, so a global union would be both large and meaningless. An unknown
// group ⇒ empty (no authority), not an error; real lookup failures propagate
// (fail-closed — never a partial set returned as if complete).
func (s *Client) ListEffectivePermissions(ctx context.Context, subject authkit.Subject, group authkit.GroupRef) ([]string, error) {
	sch := s.groupSchemaOrDefault()
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, group)
	if err != nil {
		if errors.Is(err, ErrGroupNotFound) {
			return []string{}, nil
		}
		return nil, err
	}
	return st.GrantsOnGroup(ctx, sch, subject, gid)
}

// ListGroupMembers returns the role-assignments in the group addressed by
// (persona, instanceSlug).
func (s *Client) ListGroupMembers(ctx context.Context, group authkit.GroupRef) ([]GroupMember, error) {
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, group)
	if err != nil {
		return nil, err
	}
	return st.GroupMembers(ctx, gid)
}

// ListSubjectGroups returns every group membership a subject holds (the
// cross-persona discovery behind /me/groups).
func (s *Client) ListSubjectGroups(ctx context.Context, subject authkit.Subject) ([]SubjectGroupMembership, error) {
	return s.groupStore().SubjectGroups(ctx, subject)
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
func (s *Client) DefineGroupCustomRole(ctx context.Context, actorUserID string, group authkit.GroupRef, def authkit.CustomRoleDef) error {
	sch := s.groupSchemaOrDefault()
	persona, role, permissions := group.Persona, def.Role, def.Permissions
	td, ok := sch.Persona(persona)
	if !ok {
		return fmt.Errorf("unknown group persona %q: %w", persona, authkit.ErrUnknownGroupPersona)
	}
	if !td.Capabilities.CustomRoles {
		return fmt.Errorf("group persona %q does not allow custom roles: %w", persona, authkit.ErrCustomRolesNotSupported)
	}
	if !segmentRe.MatchString(string(role)) {
		return fmt.Errorf("custom role name %q must match [a-z][a-z0-9-]*: %w", role, authkit.ErrCustomRoleNameInvalid)
	}
	if _, isCatalog := sch.Role(persona, role); isCatalog {
		return fmt.Errorf("role %q is a catalog role and cannot be redefined as custom: %w", role, authkit.ErrCustomRoleIsCatalogRole)
	}
	for _, p := range permissions {
		if err := ValidateGrantPattern(p); err != nil {
			return err
		}
		if authkit.Perm(p).Persona() != persona {
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
	gid, err := s.resolveGroupID(ctx, st, group)
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
	return st.UpsertCustomRole(ctx, gid, def)
}

// DeleteGroupCustomRole removes a custom role from a group, acting as
// actorUserID. #247 SECURITY: deleting a role is a DEFERRED REVOKE from every
// subject currently holding it, gated by the same capability + no-escalation
// rule as DefineGroupCustomRole (covering the role's stored grants; a
// not-yet-defined role has nothing to revoke, so only the capability check
// applies).
func (s *Client) DeleteGroupCustomRole(ctx context.Context, actorUserID string, group authkit.GroupRef, role authkit.Role) error {
	sch := s.groupSchemaOrDefault()
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, group)
	if err != nil {
		return err
	}
	oldGrants, _, err := st.CustomRole(ctx, gid, role)
	if err != nil {
		return err
	}
	if err := s.authorizeCustomRoleChange(ctx, st, sch, group.Persona, gid, actorUserID, oldGrants, nil); err != nil {
		return err
	}
	return st.DeleteCustomRole(ctx, gid, role)
}

func (s *Client) groupStoreFor(q db.DBTX) *PermissionGroupStore {
	st := NewPermissionGroupStore(q)
	st.now = s.namingNow
	return st
}

func (s *Client) ResolveGroupSlug(ctx context.Context, group authkit.GroupRef) (authkit.NameResolution, error) {
	return s.groupStore().ResolveGroupSlug(ctx, group)
}
