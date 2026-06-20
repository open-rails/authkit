package core

import (
	"context"
	"strings"

	"github.com/open-rails/authkit/internal/db"
)

// Platform RBAC (#95, Layer 2 — the Kubernetes ClusterRole analog). A COMPLETELY
// SEPARATE object type from org RBAC: platform roles (profiles.platform_roles)
// are assigned to users DIRECTLY (profiles.platform_user_roles), with no org and
// no membership, and grant ONLY `platform:<resource>:<action>` permissions — the
// disjoint directory/entity namespace. The two layers never overlap:
//
//   - a `platform:` perm can ONLY come from a platform role (this file);
//   - an `org:` perm can ONLY come from an org membership (org_role_permissions);
//   - ValidatePlatformGrant REJECTS any non-`platform:` token, and the org-side
//     ValidateGrant rejects any `platform:` token (it isn't in the org catalog).
//
// A user with no platform_user_roles row has ZERO platform authority, so the
// regular-user path short-circuits (PlatformUserPermissions returns empty).

// platformPermissionPrefix is the namespace owned by Layer-2 platform RBAC.
const platformPermissionPrefix = "platform:"

// Platform base permissions — the native `platform:` directory catalog (#95).
// These manage ENTITIES (accounts, orgs as whole units, the platform-admin
// roster), never an org's internals. super-admin = `platform:*` covers them all.
const (
	PermPlatformUsersRead   = "platform:users:read"   // read the global account directory
	PermPlatformUsersUpdate = "platform:users:update" // edit an account (email/username/password/sessions)
	PermPlatformUsersBan    = "platform:users:ban"    // ban / unban an account
	PermPlatformUsersDelete = "platform:users:delete" // soft-delete / restore an account

	PermPlatformOrgsRead          = "platform:orgs:read"           // the org directory (list/inspect any org as an entity)
	PermPlatformOrgsUpdate        = "platform:orgs:update"         // rename / transfer-owner of any org
	PermPlatformOrgsDelete        = "platform:orgs:delete"         // soft-delete / restore any org
	PermPlatformOrgsReservedNames = "platform:orgs:reserved-names" // restrict/unrestrict/park/claim the org slug pool
	PermPlatformOrgsRecover       = "platform:orgs:recover"        // anti-takeover reset of a compromised org

	PermPlatformRolesCreate = "platform:roles:create" // define a platform role
	PermPlatformRolesRead   = "platform:roles:read"   // list platform roles + perms
	PermPlatformRolesUpdate = "platform:roles:update" // set perms on / rename a platform role
	PermPlatformRolesDelete = "platform:roles:delete" // delete a platform role

	PermPlatformMembersCreate = "platform:members:create" // grant a user a platform role (mint a platform-admin)
	PermPlatformMembersRead   = "platform:members:read"   // list the platform-admin roster
	PermPlatformMembersDelete = "platform:members:delete" // revoke a user's platform role

	PermPlatformMetricsRead = "platform:metrics:read" // read platform metrics

	// PlatformSuperAdminGrant is the apex platform grant (super-admin): every
	// permission in the `platform:` namespace. It can NEVER reach the separate
	// `org:` layer (disjoint) — a super-admin manages entities, never an org's
	// internals.
	PlatformSuperAdminGrant = "platform:*"
)

// BasePlatformPermissions is AuthKit's native `platform:` (Layer-2) catalog.
func BasePlatformPermissions() []PermissionDef {
	return []PermissionDef{
		{Name: PermPlatformUsersRead, Description: "Read the global account directory"},
		{Name: PermPlatformUsersUpdate, Description: "Edit an account"},
		{Name: PermPlatformUsersBan, Description: "Ban or unban an account"},
		{Name: PermPlatformUsersDelete, Description: "Soft-delete or restore an account"},

		{Name: PermPlatformOrgsRead, Description: "Inspect any org as an entity (the org directory)"},
		{Name: PermPlatformOrgsUpdate, Description: "Rename or transfer ownership of any org"},
		{Name: PermPlatformOrgsDelete, Description: "Soft-delete or restore any org"},
		{Name: PermPlatformOrgsReservedNames, Description: "Manage the org slug pool (restrict/park/claim)"},
		{Name: PermPlatformOrgsRecover, Description: "Anti-takeover reset of a compromised org"},

		{Name: PermPlatformRolesCreate, Description: "Define a platform role"},
		{Name: PermPlatformRolesRead, Description: "List platform roles and their permissions"},
		{Name: PermPlatformRolesUpdate, Description: "Set permissions on a platform role"},
		{Name: PermPlatformRolesDelete, Description: "Delete a platform role"},

		{Name: PermPlatformMembersCreate, Description: "Grant a user a platform role"},
		{Name: PermPlatformMembersRead, Description: "List the platform-admin roster"},
		{Name: PermPlatformMembersDelete, Description: "Revoke a user's platform role"},

		{Name: PermPlatformMetricsRead, Description: "Read platform metrics"},
	}
}

// IsPlatformPermission reports whether name is in the `platform:` namespace.
func IsPlatformPermission(name string) bool {
	return strings.HasPrefix(strings.TrimSpace(name), platformPermissionPrefix)
}

// platformCatalogSet is the set form of the platform catalog, for glob expansion.
func (s *Service) platformCatalogSet() map[string]bool {
	m := map[string]bool{}
	for _, d := range BasePlatformPermissions() {
		m[d.Name] = true
	}
	return m
}

// PlatformPermissions returns the native `platform:` permission catalog.
func (s *Service) PlatformPermissions() []PermissionDef {
	return BasePlatformPermissions()
}

// PlatformSuperAdminRole is the conventional name of the seeded apex role.
const PlatformSuperAdminRole = "super-admin"

// EnsurePlatformSuperAdmin is the bootstrap escape-hatch for minting the FIRST
// platform-admin out-of-band (like an org's first `owner` — you can't grant a
// platform role through the platform API until someone holds one). It seeds the
// `super-admin` role (granting `platform:*`) and assigns it to userID.
// Idempotent; intended for a host's bootstrap/manifest, never a public route.
func (s *Service) EnsurePlatformSuperAdmin(ctx context.Context, userID string) error {
	if err := s.DefinePlatformRole(ctx, PlatformSuperAdminRole); err != nil {
		return err
	}
	if err := s.SetPlatformRolePermissions(ctx, PlatformSuperAdminRole, []string{PlatformSuperAdminGrant}); err != nil {
		return err
	}
	return s.AssignPlatformRole(ctx, userID, PlatformSuperAdminRole)
}

// DefinePlatformRole creates a platform role name (idempotent).
func (s *Service) DefinePlatformRole(ctx context.Context, role string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	role = strings.TrimSpace(role)
	if role == "" {
		return ErrInvalidOrgRole
	}
	return s.q.PlatformRoleUpsert(ctx, role)
}

// GetPlatformRolePermissions returns a platform role's RAW grant tokens.
func (s *Service) GetPlatformRolePermissions(ctx context.Context, role string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	return s.q.PlatformRolePermissions(ctx, strings.TrimSpace(role))
}

// SetPlatformRolePermissions replaces a platform role's permission set. The role
// must exist. Tokens are stored as-is; callers should ValidatePlatformGrant first.
func (s *Service) SetPlatformRolePermissions(ctx context.Context, role string, perms []string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	role = strings.TrimSpace(role)
	exists, err := s.q.PlatformRoleExists(ctx, role)
	if err != nil {
		return err
	}
	if !exists {
		return ErrInvalidOrgRole
	}
	clean := dedupeStrings(perms)
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.qtx(tx)
	if err := qtx.PlatformRolePermissionsDelete(ctx, role); err != nil {
		return err
	}
	for _, p := range clean {
		if err := qtx.PlatformRolePermissionInsert(ctx, db.PlatformRolePermissionInsertParams{Role: role, Permission: p}); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// DeletePlatformRole removes a platform role (and, by cascade, its perms and
// every assignment of it). Returns the number of role rows removed.
func (s *Service) DeletePlatformRole(ctx context.Context, role string) (int64, error) {
	if err := s.requirePG(); err != nil {
		return 0, err
	}
	return s.q.PlatformRoleDelete(ctx, strings.TrimSpace(role))
}

// ListPlatformRoles returns every defined platform role name.
func (s *Service) ListPlatformRoles(ctx context.Context) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	return s.q.PlatformRolesList(ctx)
}

// AssignPlatformRole grants a user a platform role (idempotent) — this is what
// mints a platform-admin. The role must exist.
func (s *Service) AssignPlatformRole(ctx context.Context, userID, role string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	userID = strings.TrimSpace(userID)
	role = strings.TrimSpace(role)
	if userID == "" || role == "" {
		return ErrInvalidOrgRole
	}
	exists, err := s.q.PlatformRoleExists(ctx, role)
	if err != nil {
		return err
	}
	if !exists {
		return ErrInvalidOrgRole
	}
	return s.q.PlatformUserRoleInsert(ctx, db.PlatformUserRoleInsertParams{UserID: userID, Role: role})
}

// UnassignPlatformRole revokes a user's platform role. Returns whether a row was
// removed.
func (s *Service) UnassignPlatformRole(ctx context.Context, userID, role string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	n, err := s.q.PlatformUserRoleDelete(ctx, db.PlatformUserRoleDeleteParams{UserID: strings.TrimSpace(userID), Role: strings.TrimSpace(role)})
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// PlatformRolesForUser returns the platform role names assigned to a user.
func (s *Service) PlatformRolesForUser(ctx context.Context, userID string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	return s.q.PlatformUserRoles(ctx, strings.TrimSpace(userID))
}

// PlatformRoleMembers returns the user ids that hold a given platform role.
func (s *Service) PlatformRoleMembers(ctx context.Context, role string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	return s.q.PlatformUserRoleMembers(ctx, strings.TrimSpace(role))
}

// EffectivePlatformPermissions returns the union of a user's platform
// permissions across all their platform roles, expanded against the platform
// catalog (globs expand; literals pass through). ONE indexed JOIN + in-memory
// expansion; a regular user (no platform roles) gets an empty set.
func (s *Service) EffectivePlatformPermissions(ctx context.Context, userID string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	toks, err := s.q.PlatformUserPermissions(ctx, strings.TrimSpace(userID))
	if err != nil {
		return nil, err
	}
	return sortedKeys(effectivePermsForTokens(toks, s.platformCatalogSet())), nil
}

// HasPlatformPermission reports whether the user holds perm in the platform layer.
func (s *Service) HasPlatformPermission(ctx context.Context, userID, perm string) (bool, error) {
	perm = strings.TrimSpace(perm)
	eff, err := s.EffectivePlatformPermissions(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, p := range eff {
		if p == perm {
			return true, nil
		}
	}
	return false, nil
}

// ValidatePlatformGrant checks tokens an actor wants to assign to a platform role
// (#94 no-escalation + #95 DISJOINT namespaces). Each token must (a) be in the
// `platform:` namespace — an `org:` perm, a bare `*`, or a `!`-negation is
// REJECTED as unknown (keeping the two layers disjoint) — and (b) expand to at
// least one platform catalog permission. No-escalation: the actor must already
// hold every concrete platform permission the token confers. `actorAll`
// short-circuits for a bootstrap/super-admin actor. Returns (unknown, offending).
func (s *Service) ValidatePlatformGrant(ctx context.Context, actorUserID string, tokens []string, actorAll bool) (unknown, offending []string, err error) {
	catalog := s.platformCatalogSet()
	var actorEff map[string]bool
	if !actorAll {
		eff, e := s.EffectivePlatformPermissions(ctx, actorUserID)
		if e != nil {
			return nil, nil, e
		}
		actorEff = map[string]bool{}
		for _, p := range eff {
			actorEff[p] = true
		}
	}
	for _, t := range dedupeStrings(tokens) {
		if t == PermWildcard || strings.HasPrefix(t, "!") || !strings.HasPrefix(t, platformPermissionPrefix) {
			// bare `*`, negation, and any non-platform: token (incl. `org:`) are
			// invalid on a platform role — the layers are disjoint.
			unknown = append(unknown, t)
			continue
		}
		expansion := make([]string, 0)
		for p := range catalog {
			if permMatches(t, p) {
				expansion = append(expansion, p)
			}
		}
		if len(expansion) == 0 {
			unknown = append(unknown, t)
			continue
		}
		if actorAll {
			continue
		}
		for _, p := range expansion {
			if !actorEff[p] {
				offending = append(offending, t)
				break
			}
		}
	}
	return unknown, offending, nil
}
