package core

import (
	"context"
	"errors"
	"sort"
	"strings"
)

// Org RBAC (authkit #46): roles are NAMES (profiles.org_roles) plus a set of
// permission strings (profiles.org_role_permissions). Permissions are OPAQUE to
// authkit — the embedding app declares its catalog and authkit adds a base set;
// authkit only stores / serves / validates set-membership, never meaning.

const (
	// PermWildcard in a role's permission set means "all catalog permissions".
	PermWildcard = "*"
	// permExcludePrefix marks an exclusion token (e.g. "!org:roles:manage"),
	// used with `*` to express "everything except". Exclusions only subtract.
	permExcludePrefix = "!"

	// reservedPermissionPrefix is the namespace authkit owns for its base
	// org-management permissions; app catalogs must not declare under it, and
	// OATs may not be scoped to them.
	reservedPermissionPrefix = "org:"

	// authkit base org-management permissions. They gate authkit's own
	// org-management endpoints via the permission system.
	PermOrgRolesManage   = "org:roles:manage"   // create/modify/delete roles + set role permissions
	PermOrgMembersManage = "org:members:manage" // add/remove members + grant/remove their roles
	PermOrgTokensManage  = "org:tokens:manage"  // mint/revoke OATs
	PermOrgRead          = "org:read"           // view members/roles/tokens
)

// ErrUnknownPermission indicates a permission not present in the catalog.
var ErrUnknownPermission = errors.New("unknown_permission")

// BasePermissions are the org-management permissions authkit defines for every
// embedding app (reserved `org:` namespace).
func BasePermissions() []PermissionDef {
	return []PermissionDef{
		{Name: PermOrgRolesManage, Description: "Create, modify, and delete org roles and their permissions"},
		{Name: PermOrgMembersManage, Description: "Add/remove org members and grant or remove their roles"},
		{Name: PermOrgTokensManage, Description: "Mint and revoke organization access tokens (OATs)"},
		{Name: PermOrgRead, Description: "View org members, roles, and access tokens"},
	}
}

// IsReservedPermission reports whether name is in authkit's reserved base
// namespace (an app catalog may not redefine these; OATs may not hold them).
func IsReservedPermission(name string) bool {
	return strings.HasPrefix(strings.TrimSpace(name), reservedPermissionPrefix)
}

// Catalog returns the full permission catalog: authkit base permissions plus the
// app-declared catalog (deduped, base wins on collision).
func (s *Service) Catalog() []PermissionDef {
	out := append([]PermissionDef{}, BasePermissions()...)
	seen := map[string]bool{}
	for _, d := range out {
		seen[d.Name] = true
	}
	for _, d := range s.opts.PermissionCatalog {
		n := strings.TrimSpace(d.Name)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, PermissionDef{Name: n, Description: d.Description})
	}
	return out
}

func (s *Service) catalogSet() map[string]bool {
	m := map[string]bool{}
	for _, d := range s.Catalog() {
		m[d.Name] = true
	}
	return m
}

// effectivePermsForTokens expands one role's stored tokens against the catalog:
// `*` => every catalog permission; `!p` => remove p; otherwise the literal
// permission. Returns the resulting set.
func effectivePermsForTokens(tokens []string, catalog map[string]bool) map[string]bool {
	out := map[string]bool{}
	excl := map[string]bool{}
	star := false
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		switch {
		case t == "":
			continue
		case t == PermWildcard:
			star = true
		case strings.HasPrefix(t, permExcludePrefix):
			excl[strings.TrimSpace(strings.TrimPrefix(t, permExcludePrefix))] = true
		default:
			out[t] = true
		}
	}
	if star {
		for p := range catalog {
			out[p] = true
		}
	}
	for p := range excl {
		delete(out, p)
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// GetRolePermissions returns a role's RAW permission tokens (may include `*` and
// `!p` exclusions).
func (s *Service) GetRolePermissions(ctx context.Context, orgSlug, role string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return nil, err
	}
	role = canonicalizeOrgRole(role)
	rows, err := s.pg.Query(ctx, `
		SELECT permission FROM profiles.org_role_permissions
		WHERE org_id=$1::uuid AND role=$2 ORDER BY permission ASC
	`, org.ID, role)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SetRolePermissions replaces a role's permission set (idempotent). The role
// must already exist (created via DefineRole). Tokens are stored as-is (opaque);
// callers should validate via ValidateGrant first for no-escalation.
func (s *Service) SetRolePermissions(ctx context.Context, orgSlug, role string, perms []string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return err
	}
	role = canonicalizeOrgRole(role)
	var exists bool
	if err := s.pg.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM profiles.org_roles WHERE org_id=$1::uuid AND role=$2)`, org.ID, role).Scan(&exists); err != nil {
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
	if _, err := tx.Exec(ctx, `DELETE FROM profiles.org_role_permissions WHERE org_id=$1::uuid AND role=$2`, org.ID, role); err != nil {
		return err
	}
	for _, p := range clean {
		if _, err := tx.Exec(ctx, `INSERT INTO profiles.org_role_permissions (org_id, role, permission) VALUES ($1::uuid,$2,$3) ON CONFLICT DO NOTHING`, org.ID, role, p); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// EffectivePermissions returns the union of permissions across all of the user's
// roles in the org, expanded against the catalog. This is the single source of
// truth for "what can this principal do" (the embedding app calls it at request
// time for enforcement — do NOT bake into the JWT).
func (s *Service) EffectivePermissions(ctx context.Context, orgSlug, userID string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	roles, err := s.ReadMemberRoles(ctx, orgSlug, userID)
	if err != nil {
		return nil, err
	}
	catalog := s.catalogSet()
	eff := map[string]bool{}
	for _, role := range roles {
		toks, err := s.GetRolePermissions(ctx, orgSlug, role)
		if err != nil {
			return nil, err
		}
		for p := range effectivePermsForTokens(toks, catalog) {
			eff[p] = true
		}
	}
	return sortedKeys(eff), nil
}

// EffectiveRolePermissions returns a single role's permissions expanded against
// the catalog (`*` => all, `!p` => exclude). Used to enforce no-escalation when
// assigning a role to a member (the assigner must hold everything the role grants).
func (s *Service) EffectiveRolePermissions(ctx context.Context, orgSlug, role string) ([]string, error) {
	toks, err := s.GetRolePermissions(ctx, orgSlug, role)
	if err != nil {
		return nil, err
	}
	return sortedKeys(effectivePermsForTokens(toks, s.catalogSet())), nil
}

// HasPermission reports whether the user holds perm in the org.
func (s *Service) HasPermission(ctx context.Context, orgSlug, userID, perm string) (bool, error) {
	perm = strings.TrimSpace(perm)
	eff, err := s.EffectivePermissions(ctx, orgSlug, userID)
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

// ValidateGrant checks a set of permission tokens an actor wants to assign to a
// role: every concrete permission must be in the catalog (else returned in
// unknown) AND within the actor's effective permissions (else returned in
// offending); `*` requires the actor to effectively hold the whole catalog;
// `!p` exclusions only subtract and are always allowed. `actorAll` short-circuits
// the no-escalation check for an actor known to hold everything (e.g. a platform
// global admin). Returns (unknown, offending).
func (s *Service) ValidateGrant(ctx context.Context, orgSlug, actorUserID string, tokens []string, actorAll bool) (unknown, offending []string, err error) {
	catalog := s.catalogSet()
	var actorEff map[string]bool
	actorHoldsAll := actorAll
	if !actorAll {
		eff, e := s.EffectivePermissions(ctx, orgSlug, actorUserID)
		if e != nil {
			return nil, nil, e
		}
		actorEff = map[string]bool{}
		for _, p := range eff {
			actorEff[p] = true
		}
		actorHoldsAll = len(catalog) > 0 && len(actorEff) >= len(catalog) && supersetOf(actorEff, catalog)
	}
	for _, t := range dedupeStrings(tokens) {
		switch {
		case t == PermWildcard:
			if !actorHoldsAll {
				offending = append(offending, t)
			}
		case strings.HasPrefix(t, permExcludePrefix):
			// exclusion only narrows; nothing to validate.
		default:
			if !catalog[t] {
				unknown = append(unknown, t)
				continue
			}
			if !actorAll && !actorEff[t] {
				offending = append(offending, t)
			}
		}
	}
	return unknown, offending, nil
}

func supersetOf(have, want map[string]bool) bool {
	for w := range want {
		if !have[w] {
			return false
		}
	}
	return true
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// seedRolePermissionDefaults seeds the built-in owner role (`*`) and every
// app-declared DefaultRole (role name + permission tokens) for a freshly created
// org. Idempotent.
func (s *Service) seedRolePermissionDefaults(ctx context.Context, orgID string) error {
	if _, err := s.pg.Exec(ctx, `
		INSERT INTO profiles.org_role_permissions (org_id, role, permission)
		VALUES ($1::uuid, $2, $3) ON CONFLICT DO NOTHING
	`, orgID, orgOwnerRole, PermWildcard); err != nil {
		return err
	}
	for _, dr := range s.opts.DefaultRoles {
		role := canonicalizeOrgRole(dr.Name)
		if role == "" || strings.EqualFold(role, orgOwnerRole) {
			continue
		}
		if _, err := s.pg.Exec(ctx, `INSERT INTO profiles.org_roles (org_id, role) VALUES ($1::uuid,$2) ON CONFLICT (org_id, role) DO NOTHING`, orgID, role); err != nil {
			return err
		}
		for _, p := range dedupeStrings(dr.Permissions) {
			if _, err := s.pg.Exec(ctx, `INSERT INTO profiles.org_role_permissions (org_id, role, permission) VALUES ($1::uuid,$2,$3) ON CONFLICT DO NOTHING`, orgID, role, p); err != nil {
				return err
			}
		}
	}
	return nil
}
