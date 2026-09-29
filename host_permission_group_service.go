package authkit

// Engine-level permission-group API (#111): the consumer entry points that wrap
// the store with the compiled role schema, owner seeding, and transaction
// scoping. Group ids stay INTERNAL — callers address groups by (persona,
// instance_slug).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/rbac"
)

// PermissionGroupSchema returns the compiled Config.Roles.
func (s *engine) PermissionGroupSchema() *rbac.Schema {
	return s.groupSchemaOrDefault()
}

var rootOnlySchema = rbac.Default()

func (s *engine) groupSchemaOrDefault() *rbac.Schema {
	if s.groupSchema != nil {
		return s.groupSchema
	}
	return rootOnlySchema
}

// KnownPermission reports whether perm is registered in a persona catalog.
func (s *engine) KnownPermission(perm iam.Perm) bool {
	return s.groupSchemaOrDefault().KnownPermission(perm)
}

// groupStore binds a PermissionGroupStore to the engine's schema-bound pool
// handle, so unqualified SQL resolves to the configured namespace (authkit #69).
func (s *engine) groupStore() *permissionGroupStore {
	return s.groupStoreFor(s.pg)
}

// initializeGroups installs the root singleton. It never assigns users roles
// or restores revoked authority. The shared authority lock and transaction
// keep concurrent construction atomic.
func (s *engine) initializeGroups() error {
	if s.pg == nil {
		return nil
	}
	ctx := context.Background()
	if err := s.withAuthorityMutation(ctx, func(st *permissionGroupStore) error {
		_, err := st.ensureRootGroup(ctx)
		return err
	}); err != nil {
		return fmt.Errorf("authkit: initialize permission groups (apply migrations before New): %w", err)
	}
	s.logRBACDrift(ctx)
	return nil
}

func (s *engine) logRBACDrift(ctx context.Context) {
	if report, err := s.RBACDriftReport(ctx); err == nil && report.Total() > 0 {
		slog.Default().Warn("authkit: rbac drift detected",
			"group_user_roles", report.GroupUserRoles,
			"group_custom_roles", report.CustomRoles,
			"api_keys", report.APIKeys,
		)
	}
}

// EnsureRootGroup creates the singleton root group if absent (idempotent) and
// returns its internal id. Concurrent cold boots race the singleton index; the
// loser adopts the winner's row instead of failing (#258).
func (s *engine) EnsureRootGroup(ctx context.Context) (string, error) {
	return s.groupStore().ensureRootGroup(ctx)
}

func (st *permissionGroupStore) ensureRootGroup(ctx context.Context) (string, error) {
	id, err := st.RootGroupID(ctx)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, iam.ErrGroupNotFound) {
		return "", err
	}
	// DO NOTHING keeps a concurrent singleton insert from aborting a caller's
	// enclosing transaction. Root has no mutable name claim.
	err = st.q.QueryRow(ctx, `INSERT INTO permission_groups (persona)
		VALUES ('root') ON CONFLICT DO NOTHING RETURNING id::text`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return st.RootGroupID(ctx)
	}
	return id, err
}

// CreatePermissionGroup creates a group of a declared non-root persona and
// (atomically) seeds the owner assignment. Returns the INTERNAL group id (for
// the caller's own bookkeeping; never exposed over the wire).
func (s *engine) CreatePermissionGroup(ctx context.Context, req iam.CreatePermissionGroupRequest) (string, error) {
	group := iam.GroupBySlug(req.Persona, req.InstanceSlug)
	req.Persona, req.InstanceSlug = group.Persona(), group.Slug()
	if _, ok := s.groupSchemaOrDefault().Persona(req.Persona); !ok || group.IsRoot() {
		return "", fmt.Errorf("unknown group persona %q: %w", req.Persona, iam.ErrUnknownGroupPersona)
	}
	if err := iam.ValidateGroupInstanceSlug(group); err != nil {
		return "", err
	}

	tx, err := s.beginAuthorityTransaction(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.groupStoreFor(tx)
	if err := s.lockAuthority(ctx, st.q); err != nil {
		return "", err
	}

	id, err := st.CreateGroupNamed(ctx, group, strings.TrimSpace(req.DisplayName))
	if err != nil {
		return "", err
	}
	if req.OwnerSubjectID != "" {
		// #264 service-owned orgs: the owner may be a user (default) or a
		// remote-application principal.
		owner := iam.Subject{ID: req.OwnerSubjectID, Kind: req.OwnerSubjectKind}
		if owner.Kind == "" {
			owner.Kind = iam.SubjectKindUser
		}
		if _, _, err := groupRoleTable(owner.Kind); err != nil {
			return "", err
		}
		if err := s.requireMFAForRoleAssignment(ctx, tx, id, req.Persona, owner, iam.OwnerRole); err != nil {
			return "", fmt.Errorf("seed owner: %w", err)
		}
		if err := st.AssignRole(ctx, id, owner, iam.OwnerRole); err != nil {
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
func (s *engine) SetPermissionGroupDisplayName(ctx context.Context, group iam.GroupRef, displayName string) error {
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
func (s *engine) UpdateGroupInstanceAs(ctx context.Context, actorUserID, groupID string, update iam.GroupInstanceUpdate) (iam.GroupInstance, error) {
	var out iam.GroupInstance
	if err := s.requirePG(); err != nil {
		return out, err
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.groupStoreFor(tx)
	var persona iam.Persona
	var current string
	if err := st.q.QueryRow(ctx, `SELECT persona,COALESCE(instance_slug,'') FROM permission_groups WHERE id=$1::uuid AND deleted_at IS NULL FOR UPDATE`, groupID).Scan(&persona, &current); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return out, iam.ErrGroupNotFound
		}
		return out, err
	}
	allowed, err := st.CanOnGroup(ctx, s.groupSchemaOrDefault(), iam.UserSubject(actorUserID), groupID, iam.PermSelfUpdate(persona))
	if err != nil {
		return out, err
	}
	if !allowed {
		return out, iam.ErrInsufficientRoleAuthority
	}
	if update.Slug != nil {
		newSlug := strings.ToLower(strings.TrimSpace(*update.Slug))
		if persona == iam.RootPersona {
			return out, iam.ErrUnknownGroupPersona
		}
		if newSlug != current {
			if err := s.authorizeSlugClaim(ctx, s.groupSchemaOrDefault(), iam.GroupBySlug(persona, newSlug), actorUserID); err != nil {
				return out, err
			}
			var managed bool
			if err := st.q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM remote_applications WHERE permission_group_id=$1::uuid AND trust_root='domain')`, groupID).Scan(&managed); err != nil {
				return out, err
			}
			if managed {
				return out, iam.ErrGroupSlugApplicationManaged
			}
			if err := s.admitName(ctx, iam.NameAdmissionRequest{OwnerKind: "group", Persona: persona, OwnerID: groupID, ActorID: actorUserID, CurrentName: current, RequestedName: newSlug, Operation: iam.NameRename}); err != nil {
				return out, err
			}
			if err := st.renameGroupSlug(ctx, groupID, newSlug, s.NamingPolicy()); err != nil {
				return out, err
			}
		}
	}
	if update.DisplayName != nil {
		if len(*update.DisplayName) > 256 {
			return out, iam.ErrGroupSlugInvalid
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

// resolveGroupID is resolveGroup's id.
func (s *engine) resolveGroupID(ctx context.Context, st *permissionGroupStore, g iam.GroupRef) (string, error) {
	t, err := s.resolveGroup(ctx, st, g)
	return t.ID, err
}

// ResolveGroupIDForSlug maps the API addressing key (persona, instanceSlug) to
// the group's INTERNAL id, for IN-PROCESS callers that must thread the
// controlling permission_group_id into a sibling resource (e.g. a
// remote_application's permission_group_id, #111). ErrGroupNotFound if no live
// group matches. Out-of-process callers use GroupInstanceForSlug, which the
// HTTP descriptor route exposes under an authorization gate (#269).
func (s *engine) ResolveGroupIDForSlug(ctx context.Context, group iam.GroupRef) (string, error) {
	if err := s.requirePG(); err != nil {
		return "", err
	}
	return s.resolveGroupID(ctx, s.groupStore(), group)
}

// GroupInstanceForSlug reads one instance's own identity — id, persona, slug,
// display name (#269). This is the read behind GET /<persona>/:instance_slug:
// the id is a JOIN KEY a host needs for its own ledger rows, never an address.
// Authorization is the caller's job (the route gates on <persona>:self:read).
func (s *engine) GroupInstanceForSlug(ctx context.Context, group iam.GroupRef) (iam.GroupInstance, error) {
	if err := s.requirePG(); err != nil {
		return iam.GroupInstance{}, err
	}
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, group)
	if err != nil {
		return iam.GroupInstance{}, err
	}
	return st.GroupInstanceByID(ctx, gid)
}

// validRoleForPersona reports whether role is assignable in a group of persona: a
// catalog role, or any role when the persona allows custom roles (custom roles are
// validated at definition time).
func (s *engine) validRoleForPersona(sch *rbac.Schema, persona iam.Persona, role iam.Role) bool {
	role = iam.Role(strings.TrimSpace(string(role)))
	if role == "" {
		return false
	}
	if _, ok := sch.Role(persona, role); ok {
		return true
	}
	td, ok := sch.Persona(persona)
	return ok && td.CustomRoles
}

// DeletePermissionGroup deletes a group instance (role assignments, api keys,
// and remote applications cascade). Delete-time naming rule (#264
// ruling 5): by DEFAULT the slug is TOMBSTONED to the group uuid forever —
// fail-safe, published references can never be re-claimed. Passing
// ReleaseSlug frees every deleted canonical name instead; that is safe ONLY for names nothing
// ever referenced, and the judgment is the host's. authkit itself never
// deletes a group — dormancy policy is entirely host-side.
func (s *engine) DeletePermissionGroup(ctx context.Context, group iam.GroupRef, opts iam.DeletePermissionGroupOptions) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	if group.IsRoot() {
		return fmt.Errorf("the root group cannot be deleted: %w", iam.ErrUnknownGroupPersona)
	}
	tx, err := s.beginAuthorityTransaction(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.groupStoreFor(tx)
	if err := s.lockAuthority(ctx, st.q); err != nil {
		return err
	}
	gid, bound, err := st.requestGroupID(ctx, group)
	if !bound {
		gid, err = st.GroupByLiveInstanceSlug(ctx, group)
	}
	if err != nil {
		return err
	}
	if err := s.deleteGroupTx(ctx, st, gid, opts); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Can is the engine-level authorization check: resolve the group addressed by
// (persona, instanceSlug), then test perm coverage over the subject's roles on
// that group and on root. An unregistered perm is ErrUnknownPermission.
func (s *engine) Can(ctx context.Context, subject iam.Subject, group iam.GroupRef, perm iam.Perm) (bool, error) {
	sch := s.groupSchemaOrDefault()
	if !sch.KnownPermission(perm) {
		return false, fmt.Errorf("%w: %q", iam.ErrUnknownPermission, perm)
	}
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, group)
	if err != nil {
		if errors.Is(err, iam.ErrGroupNotFound) {
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
// iam.Perm.Matches the server enforces with) instead of re-deriving authority
// from role slugs. Scoped per group instance BY DESIGN — perms are persona-
// namespaced, so a global union would be both large and meaningless. An unknown
// group ⇒ empty (no authority), not an error; real lookup failures propagate
// (fail-closed — never a partial set returned as if complete). This describes
// assigned grants, including latent authority on deleted/reserved accounts;
// Can additionally requires a present native account before granting access.
func (s *engine) ListEffectivePermissions(ctx context.Context, subject iam.Subject, group iam.GroupRef) ([]iam.Perm, error) {
	gid, err := s.resolveGroupID(ctx, s.groupStore(), group)
	if err != nil {
		if errors.Is(err, iam.ErrGroupNotFound) {
			return []iam.Perm{}, nil
		}
		return nil, err
	}
	perms, err := s.EffectivePermissionsForGroups(ctx, subject, []string{gid})
	if err != nil {
		return nil, err
	}
	if p := perms[gid]; p != nil {
		return p, nil
	}
	return []iam.Perm{}, nil
}

// ListGroupMembers returns the role-assignments in the group addressed by
// (persona, instanceSlug).
func (s *engine) ListGroupMembers(ctx context.Context, group iam.GroupRef) ([]iam.GroupMember, error) {
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, group)
	if err != nil {
		return nil, err
	}
	return st.GroupMembers(ctx, gid)
}

// ListSubjectGroups returns every group membership a subject holds (the
// cross-persona discovery behind /me/groups).
func (s *engine) ListSubjectGroups(ctx context.Context, subject iam.Subject) ([]iam.SubjectGroupMembership, error) {
	return s.groupStore().SubjectGroups(ctx, subject)
}

// DefineGroupCustomRole creates/updates a custom role in the group addressed by
// (persona, instanceSlug), acting as actorUserID. Requires the persona to allow
// custom roles; every permission must match the persona's catalog, and the
// name must not collide with a declared role. requiresMFA mirrors Role.RequiresMFA for catalog roles (#247).
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
func (s *engine) DefineGroupCustomRole(ctx context.Context, actorUserID string, group iam.GroupRef, def authflow.CustomRoleDef) error {
	sch := s.groupSchemaOrDefault()
	persona, role, permissions := group.Persona(), def.Role, def.Permissions
	td, ok := sch.Persona(persona)
	if !ok {
		return fmt.Errorf("unknown group persona %q: %w", persona, iam.ErrUnknownGroupPersona)
	}
	if !td.CustomRoles {
		return fmt.Errorf("group persona %q does not allow custom roles: %w", persona, iam.ErrCustomRolesNotSupported)
	}
	if !iam.ValidPermissionSegment(string(role)) {
		return fmt.Errorf("custom role name %q must match [a-z][a-z0-9-]*: %w", role, iam.ErrCustomRoleNameInvalid)
	}
	if _, isCatalog := sch.Role(persona, role); isCatalog {
		return fmt.Errorf("role %q is a catalog role and cannot be redefined as custom: %w", role, iam.ErrCustomRoleIsCatalogRole)
	}
	if err := sch.CustomRoleGrantsValid(persona, permissions); err != nil {
		return err
	}
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, group)
	if err != nil {
		return err
	}
	return s.withLockedGroup(ctx, gid, func(st *permissionGroupStore) error {
		oldGrants, _, err := st.CustomRole(ctx, gid, role)
		if err != nil {
			return err
		}
		if err := s.authorizeCustomRoleChange(ctx, st, groupTarget{ID: gid, Persona: persona}, actorUserID, oldGrants, permissions); err != nil {
			return err
		}
		return st.UpsertCustomRole(ctx, gid, def)
	})
}

// DeleteGroupCustomRole removes a custom role from a group, acting as
// actorUserID. Deletion retires every stored reference in one transaction,
// gated by the existing capability + no-escalation
// rule as DefineGroupCustomRole (covering the role's stored grants; a
// not-yet-defined role has nothing to revoke, so only the capability check
// applies).
func (s *engine) DeleteGroupCustomRole(ctx context.Context, actorUserID string, group iam.GroupRef, role iam.Role) error {
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, group)
	if err != nil {
		return err
	}
	return s.withLockedGroup(ctx, gid, func(st *permissionGroupStore) error {
		oldGrants, _, err := st.CustomRole(ctx, gid, role)
		if err != nil {
			return err
		}
		if err := s.authorizeCustomRoleChange(ctx, st, groupTarget{ID: gid, Persona: group.Persona()}, actorUserID, oldGrants, nil); err != nil {
			return err
		}
		return st.DeleteCustomRole(ctx, gid, role)
	})
}

func (s *engine) groupStoreFor(q db.DBTX) *permissionGroupStore {
	st := newPermissionGroupStore(q)
	st.now = s.namingNow
	return st
}

func (s *engine) ResolveGroupSlug(ctx context.Context, group iam.GroupRef) (iam.NameResolution, error) {
	return s.groupStore().ResolveGroupSlug(ctx, group)
}
