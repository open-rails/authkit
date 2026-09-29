package engine

// Permission groups: the compiled role schema, the root singleton, live
// permission checks and custom roles.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/rbac"
)

// PermissionGroupSchema returns the compiled Config.Roles.
func (s *Engine) PermissionGroupSchema() *rbac.Schema {
	return s.groupSchemaOrDefault()
}

var rootOnlySchema = rbac.Default()

func (s *Engine) groupSchemaOrDefault() *rbac.Schema {
	if s.groupSchema != nil {
		return s.groupSchema
	}
	return rootOnlySchema
}

// KnownPermission reports whether perm is registered in a persona catalog.
func (s *Engine) KnownPermission(perm iam.Perm) bool {
	return s.groupSchemaOrDefault().KnownPermission(perm)
}

// groupStore binds a PermissionGroupStore to the engine's schema-bound pool
// handle, so unqualified SQL resolves to the configured namespace (authkit #69).
func (s *Engine) groupStore() *permissionGroupStore {
	return s.groupStoreFor(s.pg)
}

func (s *Engine) groupStoreFor(q db.DBTX) *permissionGroupStore {
	st := newPermissionGroupStore(q)
	st.now = s.namingNow
	return st
}

// initializeGroups installs the root singleton. It never assigns users roles
// or restores revoked authority. The shared authority lock and transaction
// keep concurrent construction atomic.
func (s *Engine) initializeGroups(ctx context.Context) error {
	if s.pg == nil {
		return nil
	}
	if err := s.withAuthorityMutation(ctx, func(st *permissionGroupStore) error {
		_, err := st.ensureRootGroup(ctx)
		return err
	}); err != nil {
		return fmt.Errorf("authkit: initialize permission groups (apply migrations before New): %w", err)
	}
	s.logRBACDrift(ctx)
	return nil
}

func (s *Engine) logRBACDrift(ctx context.Context) {
	if report, err := s.driftReport(ctx); err == nil && report.Total() > 0 {
		slog.Default().Warn("authkit: rbac drift detected",
			"group_user_roles", report.GroupUserRoles,
			"group_custom_roles", report.CustomRoles,
			"api_keys", report.APIKeys,
		)
	}
}

// ensureRootGroup creates the singleton root group if absent (idempotent) and
// returns its internal id. Concurrent cold boots race the singleton index; the
// loser adopts the winner's row instead of failing (#258).
func (s *Engine) ensureRootGroup(ctx context.Context) (string, error) {
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

// validRoleForPersona reports whether role is assignable in a group of persona: a
// catalog role, or any role when the persona allows custom roles (custom roles are
// validated at definition time).
func (s *Engine) validRoleForPersona(sch *rbac.Schema, persona iam.Persona, role iam.Role) bool {
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

// Can reports whether a covers perm in the group ref addresses, live: a dead
// actor, an unknown group or an actor bound to another group is false. An
// operator is always true. An unregistered perm is ErrUnknownPermission.
func (s *Engine) Can(ctx context.Context, a iam.Actor, ref iam.GroupRef, perm iam.Perm) (bool, error) {
	if !s.KnownPermission(perm) {
		return false, fmt.Errorf("%w: %q", iam.ErrUnknownPermission, perm)
	}
	if a.IsZero() || validateGroupSlug(ref) != nil {
		return false, nil
	}
	if err := s.requirePG(); err != nil {
		return false, err
	}
	st := s.groupStore()
	g, err := s.resolveGroup(ctx, st, ref)
	if errors.Is(err, iam.ErrGroupNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	auth, err := s.actorAuthority(ctx, st, a, g)
	if errors.Is(err, iam.ErrInsufficientAuthority) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return auth.covers(perm), nil
}

// EffectivePermissions returns a's effective grant patterns per group id, for
// clients that gate UI on permission strings (glob-matching with
// iam.Perm.Matches). Globs are returned verbatim; a ceiling narrows them.
// Unknown and deleted groups and groups granting nothing are absent; a dead
// actor has none. An operator gets each persona's owner grant. A user's
// grants on many groups are read in one query.
func (s *Engine) EffectivePermissions(ctx context.Context, a iam.Actor, refs []iam.GroupRef) (map[string][]iam.Perm, error) {
	if len(refs) > iam.MaxBatch {
		return nil, fmt.Errorf("batch has %d groups; at most %d", len(refs), iam.MaxBatch)
	}
	out := map[string][]iam.Perm{}
	if a.IsZero() || len(refs) == 0 {
		return out, nil
	}
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	st := s.groupStore()
	ids := make([]string, 0, len(refs))
	for _, ref := range refs {
		if id := ref.ID(); id != "" {
			if u, err := uuid.Parse(id); err == nil {
				ids = append(ids, u.String())
			}
			continue
		}
		if validateGroupSlug(ref) != nil {
			continue
		}
		g, err := s.resolveGroup(ctx, st, ref)
		if errors.Is(err, iam.ErrGroupNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		ids = append(ids, g.ID)
	}
	if userID, ok := s.actorUser(a); ok {
		subject := iam.UserSubject(userID)
		if !isUUID(userID) {
			return out, nil
		}
		live, err := subjectUsable(ctx, st.q, subject)
		if err != nil || !live {
			return out, err
		}
		byGroup, err := st.GrantsOnGroups(ctx, s.groupSchemaOrDefault(), subject, ids)
		if err != nil {
			return nil, err
		}
		for gid, grants := range byGroup {
			if perms := s.effectiveGrants(authority{actor: a, grants: grants}, groupTarget{ID: gid}); len(perms) > 0 {
				out[gid] = perms
			}
		}
		return out, nil
	}
	groups, err := st.groupsByID(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if g.DeletedAt != nil {
			continue
		}
		t := groupTarget{ID: g.ID, Persona: g.Persona, Slug: g.Slug}
		auth, err := s.actorAuthority(ctx, st, a, t)
		if errors.Is(err, iam.ErrInsufficientAuthority) {
			return map[string][]iam.Perm{}, nil
		}
		if err != nil {
			return nil, err
		}
		if perms := s.effectiveGrants(auth, t); len(perms) > 0 {
			out[g.ID] = perms
		}
	}
	return out, nil
}

// actorUser is the user whose grants a acts with: a user, or a delegation
// this deployment issued for one.
func (s *Engine) actorUser(a iam.Actor) (string, bool) {
	switch a.Kind() {
	case iam.ActorUser:
		return a.ID(), true
	case iam.ActorDelegated:
		grant, _ := a.Delegation()
		return grant.Subject, grant.RemoteApplicationID == "" && grant.Issuer == strings.TrimSpace(s.cfg.Token.Issuer)
	}
	return "", false
}

// effectiveGrants is auth's grants narrowed by its ceiling: a grant the
// ceiling fully permits stays a pattern; otherwise only the catalog
// permissions it names that the ceiling permits remain.
func (s *Engine) effectiveGrants(auth authority, g groupTarget) []iam.Perm {
	if auth.operator {
		return []iam.Perm{g.Persona.OwnerGrant()}
	}
	sch := s.groupSchemaOrDefault()
	var out []iam.Perm
	seen := map[iam.Perm]bool{}
	add := func(p iam.Perm) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, grant := range auth.grants {
		if auth.actor.CeilingCovers(iam.Perm(grant)) {
			add(iam.Perm(grant))
			continue
		}
		persona, _ := sch.Persona(iam.Perm(grant).Persona())
		for _, perm := range persona.Permissions {
			if perm.Matches(iam.Perm(grant)) && auth.actor.CeilingCovers(perm) {
				add(perm)
			}
		}
	}
	return out
}

// DefineGroupRole creates or redefines a custom role in a group whose persona
// allows them. A redefinition is a deferred grant or revoke to every holder,
// so the actor needs <p>:roles:manage and COVER of both the current and the
// new permissions, plus <p>:members:manage when users hold the role and
// <p>:credentials:manage when applications or API keys do (invite links
// carrying it count as members). A name that live rows still reference
// without a definition (a catalog role removed from config) is refused, so a
// new definition never silently re-binds those holders. Permissions that need
// MFA are refused while a holder cannot present it.
func (s *Engine) DefineGroupRole(ctx context.Context, a iam.Actor, ref iam.GroupRef, r iam.CustomRole) error {
	if err := requireActor(a); err != nil {
		return err
	}
	role := iam.Role(strings.TrimSpace(string(r.Name)))
	if !iam.ValidPermissionSegment(string(role)) {
		return fmt.Errorf("custom role name %q must match [a-z][a-z0-9-]*: %w", role, iam.ErrCustomRoleNameInvalid)
	}
	grants := make([]string, 0, len(r.Permissions))
	for _, p := range r.Permissions {
		grants = append(grants, strings.TrimSpace(p))
	}
	sch := s.groupSchemaOrDefault()
	return s.withGroupMutation(ctx, ref, func(st *permissionGroupStore, g groupTarget) error {
		if err := customRolesAllowed(sch, g.Persona, role); err != nil {
			return err
		}
		if err := sch.CustomRoleGrantsValid(g.Persona, grants); err != nil {
			return err
		}
		old, exists, err := st.CustomRole(ctx, g.ID, role)
		if err != nil {
			return err
		}
		refs, err := st.roleReferences(ctx, g.ID, role)
		if err != nil {
			return err
		}
		if !exists && refs.any() {
			return fmt.Errorf("role %q is still held under a definition that no longer exists: %w", role, iam.ErrCustomRoleIsCatalogRole)
		}
		if err := s.authorizeCustomRoleChange(ctx, st, a, g, refs, old, grants); err != nil {
			return err
		}
		if err := s.requireHoldersMFA(ctx, st, g, role, refs, grants); err != nil {
			return err
		}
		return st.UpsertCustomRole(ctx, g.ID, role, grants)
	})
}

// DeleteGroupRole deletes a custom role and every reference to it (holders,
// API keys, invite links), under DefineGroupRole's authority rule over its
// current permissions. Deleting an undefined role is a no-op.
func (s *Engine) DeleteGroupRole(ctx context.Context, a iam.Actor, ref iam.GroupRef, role iam.Role) error {
	if err := requireActor(a); err != nil {
		return err
	}
	role = iam.Role(strings.TrimSpace(string(role)))
	sch := s.groupSchemaOrDefault()
	return s.withGroupMutation(ctx, ref, func(st *permissionGroupStore, g groupTarget) error {
		if err := customRolesAllowed(sch, g.Persona, role); err != nil {
			return err
		}
		old, exists, err := st.CustomRole(ctx, g.ID, role)
		if err != nil {
			return err
		}
		refs, err := st.roleReferences(ctx, g.ID, role)
		if err != nil {
			return err
		}
		if err := s.authorizeCustomRoleChange(ctx, st, a, g, refs, old, nil); err != nil || !exists {
			return err
		}
		return st.DeleteCustomRole(ctx, g.ID, role)
	})
}

func customRolesAllowed(sch *rbac.Schema, persona iam.Persona, role iam.Role) error {
	td, ok := sch.Persona(persona)
	if !ok {
		return fmt.Errorf("unknown group persona %q: %w", persona, iam.ErrUnknownGroupPersona)
	}
	if !td.CustomRoles {
		return fmt.Errorf("group persona %q does not allow custom roles: %w", persona, iam.ErrCustomRolesNotSupported)
	}
	if _, isCatalog := sch.Role(persona, role); isCatalog {
		return fmt.Errorf("role %q is a catalog role and cannot be redefined as custom: %w", role, iam.ErrCustomRoleIsCatalogRole)
	}
	return nil
}

// authorizeCustomRoleChange is the capability and COVER rule of a custom-role
// definition or deletion.
func (s *Engine) authorizeCustomRoleChange(ctx context.Context, st *permissionGroupStore, a iam.Actor, g groupTarget, refs roleRefs, oldGrants, newGrants []string) error {
	auth, err := s.actorAuthority(ctx, st, a, g)
	if err != nil {
		return err
	}
	caps := []iam.Perm{iam.PermRolesManage(g.Persona)}
	if refs.users > 0 || refs.invites > 0 {
		caps = append(caps, iam.PermMembersManage(g.Persona))
	}
	if refs.applications > 0 || refs.apiKeys > 0 {
		caps = append(caps, iam.PermCredentialsManage(g.Persona))
	}
	for _, p := range caps {
		if err := auth.requireCap(p); err != nil {
			return err
		}
	}
	if err := auth.requireCover(oldGrants); err != nil {
		return err
	}
	return auth.requireCover(newGrants)
}

// requireHoldersMFA refuses a definition whose permissions need MFA while a
// user holding the role has none, or an application or API key holds it.
func (s *Engine) requireHoldersMFA(ctx context.Context, st *permissionGroupStore, g groupTarget, role iam.Role, refs roleRefs, grants []string) error {
	if !s.TwoFactorEnabled() || !s.groupSchemaOrDefault().RequiresMFA(grants) {
		return nil
	}
	if refs.applications > 0 || refs.apiKeys > 0 {
		return fmt.Errorf("role %q would need MFA, which applications and API keys holding it cannot provide: %w", role, iam.ErrRoleNotAssignable)
	}
	var missing bool
	err := st.q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM group_user_roles r WHERE r.permission_group_id=$1::uuid AND r.role=$2
 AND NOT EXISTS(SELECT 1 FROM mfa_settings m WHERE m.user_id=r.user_id AND m.enabled AND EXISTS(SELECT 1 FROM mfa_factors f WHERE f.user_id=r.user_id)))`, g.ID, role).Scan(&missing)
	if err != nil {
		return err
	}
	if missing {
		return iam.ErrTwoFAEnrollmentRequired
	}
	return nil
}

// refuseMFACredential: an API key cannot present a second factor, so it may
// not carry a role whose permissions need one.
func (s *Engine) refuseMFACredential(role iam.Role, grants []string) error {
	if s.TwoFactorEnabled() && s.groupSchemaOrDefault().RequiresMFA(grants) {
		return fmt.Errorf("role %q needs MFA, which an API key cannot provide: %w", role, iam.ErrRoleNotAssignable)
	}
	return nil
}
