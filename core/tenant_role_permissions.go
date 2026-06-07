package core

import (
	"context"
	"errors"
	"sort"
	"strings"
)

// Tenant RBAC (authkit #46): roles are NAMES (profiles.tenant_roles) plus a set of
// permission strings (profiles.tenant_role_permissions). Permissions are OPAQUE to
// authkit — the embedding app declares its catalog and authkit adds a base set;
// authkit only stores / serves / validates set-membership, never meaning.

const (
	// PermWildcard in a role's permission set means "all catalog permissions".
	PermWildcard = "*"
	// permExcludePrefix marks an exclusion token (e.g. "!tenant:roles:manage"),
	// used with `*` to express "everything except". Exclusions only subtract.
	permExcludePrefix = "!"

	// reservedPermissionPrefix is the namespace authkit owns for its base
	// tenant-management permissions; app catalogs must not declare under it, and
	// service tokens may not be scoped to them.
	reservedPermissionPrefix = "tenant:"

	// authkit base tenant-management permissions. They gate authkit's own
	// tenant-management endpoints via the permission system.
	PermTenantRolesManage   = "tenant:roles:manage"          // create/modify/delete roles + set role permissions
	PermTenantMembersManage = "tenant:members:manage"        // add/remove members + grant/remove their roles
	PermTenantTokensManage  = "tenant:service_tokens:manage" // mint/revoke service tokens
	PermTenantRead          = "tenant:read"                  // view members/roles/tokens
)

// ErrUnknownPermission indicates a permission not present in the catalog.
var ErrUnknownPermission = errors.New("unknown_permission")

// BasePermissions are the tenant-management permissions authkit defines for every
// embedding app (reserved `tenant:` namespace).
func BasePermissions() []PermissionDef {
	return []PermissionDef{
		{Name: PermTenantRolesManage, Description: "Create, modify, and delete tenant roles and their permissions"},
		{Name: PermTenantMembersManage, Description: "Add/remove tenant members and grant or remove their roles"},
		{Name: PermTenantTokensManage, Description: "Mint and revoke service tokens (service tokens)"},
		{Name: PermTenantRead, Description: "View tenant members, roles, and service tokens"},
	}
}

// IsReservedPermission reports whether name is in authkit's reserved base
// namespace (an app catalog may not redefine these; service tokens may not hold them
// unless service token-grantable, see IsServiceTokenGrantableReservedPermission).
func IsReservedPermission(name string) bool {
	return strings.HasPrefix(strings.TrimSpace(name), reservedPermissionPrefix)
}

// serviceTokenGrantableReservedPermissions are the reserved base permissions a service token MAY
// hold. Only read-only perms qualify: the write/mint management perms
// (tenant:roles:manage, tenant:members:manage, tenant:service_tokens:manage) stay user-only so
// a service token can never bootstrap broader authority — it cannot mint another service token,
// redefine roles, or alter membership. tenant:read is escalation-harmless and
// unblocks read-only automation (monitoring/audit bots listing members/roles).
var serviceTokenGrantableReservedPermissions = map[string]bool{
	PermTenantRead: true,
}

// IsServiceTokenGrantableReservedPermission reports whether a reserved `tenant:` permission
// may be granted to a service token. Returns false for non-reserved names.
func IsServiceTokenGrantableReservedPermission(name string) bool {
	return serviceTokenGrantableReservedPermissions[strings.TrimSpace(name)]
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
func (s *Service) GetRolePermissions(ctx context.Context, tenantSlug, role string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return nil, err
	}
	role = canonicalizeTenantRole(role)
	rows, err := s.pg.Query(ctx, `
		SELECT permission FROM profiles.tenant_role_permissions
		WHERE tenant_id=$1::uuid AND role=$2 ORDER BY permission ASC
	`, tenant.ID, role)
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
func (s *Service) SetRolePermissions(ctx context.Context, tenantSlug, role string, perms []string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return err
	}
	role = canonicalizeTenantRole(role)
	var exists bool
	if err := s.pg.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM profiles.tenant_roles WHERE tenant_id=$1::uuid AND role=$2)`, tenant.ID, role).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrInvalidTenantRole
	}
	clean := dedupeStrings(perms)
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM profiles.tenant_role_permissions WHERE tenant_id=$1::uuid AND role=$2`, tenant.ID, role); err != nil {
		return err
	}
	for _, p := range clean {
		if _, err := tx.Exec(ctx, `INSERT INTO profiles.tenant_role_permissions (tenant_id, role, permission) VALUES ($1::uuid,$2,$3) ON CONFLICT DO NOTHING`, tenant.ID, role, p); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// EffectivePermissions returns the union of permissions across all of the user's
// roles in the tenant, expanded against the catalog. This is the single source of
// truth for "what can this principal do" (the embedding app calls it at request
// time for enforcement — do NOT bake into the JWT).
func (s *Service) EffectivePermissions(ctx context.Context, tenantSlug, userID string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	roles, err := s.ReadMemberRoles(ctx, tenantSlug, userID)
	if err != nil {
		return nil, err
	}
	catalog := s.catalogSet()
	eff := map[string]bool{}
	for _, role := range roles {
		toks, err := s.GetRolePermissions(ctx, tenantSlug, role)
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
func (s *Service) EffectiveRolePermissions(ctx context.Context, tenantSlug, role string) ([]string, error) {
	toks, err := s.GetRolePermissions(ctx, tenantSlug, role)
	if err != nil {
		return nil, err
	}
	return sortedKeys(effectivePermsForTokens(toks, s.catalogSet())), nil
}

// HasPermission reports whether the user holds perm in the tenant.
func (s *Service) HasPermission(ctx context.Context, tenantSlug, userID, perm string) (bool, error) {
	perm = strings.TrimSpace(perm)
	eff, err := s.EffectivePermissions(ctx, tenantSlug, userID)
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
func (s *Service) ValidateGrant(ctx context.Context, tenantSlug, actorUserID string, tokens []string, actorAll bool) (unknown, offending []string, err error) {
	catalog := s.catalogSet()
	var actorEff map[string]bool
	actorHoldsAll := actorAll
	if !actorAll {
		eff, e := s.EffectivePermissions(ctx, tenantSlug, actorUserID)
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
			// A concrete permission is valid if it is in the catalog, OR it is
			// a RESOURCE-SCOPED grant "<resource>:<action>:<name>" whose
			// "<resource>:<action>" base is in the catalog (e.g. repo:write:my-model
			// validates against repo:write). The app interprets the <name>;
			// authkit only checks the base is a real permission. Reserved
			// 3-segment base perms (tenant:roles:manage, ...) match catalog[t]
			// directly and are not re-split.
			base := t
			if !catalog[t] {
				if parts := strings.SplitN(t, ":", 3); len(parts) == 3 {
					base = parts[0] + ":" + parts[1]
				}
			}
			if !catalog[base] {
				unknown = append(unknown, t)
				continue
			}
			// No-escalation: the actor must hold the exact scoped perm OR its
			// tenant-wide base (holding repo:write lets you grant repo:write:x).
			if !actorAll && !actorEff[t] && !actorEff[base] {
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

// seedRolePermissionDefaults seeds the built-in owner role permissions (`*`) for
// a freshly created (or claimed) tenant. App-declared DefaultRoles are NOT
// seeded eagerly — they are role TEMPLATES for human teammates and are
// materialized LAZILY the first time the role is granted (see
// materializeDefaultRole), so a solo tenant carries no dormant app-role
// scaffolding. Idempotent.
func (s *Service) seedRolePermissionDefaults(ctx context.Context, tenantID string) error {
	_, err := s.pg.Exec(ctx, `
		INSERT INTO profiles.tenant_role_permissions (tenant_id, role, permission)
		VALUES ($1::uuid, $2, $3) ON CONFLICT DO NOTHING
	`, tenantID, tenantOwnerRole, PermWildcard)
	return err
}

// materializeDefaultRole lazily seeds an app-declared DefaultRole's permission
// template into the tenant the first time that role is needed (e.g. on grant), if
// it isn't already present. No-op for the owner role, unknown roles, or roles
// that already have permissions. Idempotent.
func (s *Service) materializeDefaultRole(ctx context.Context, tenantID, role string) error {
	role = canonicalizeTenantRole(role)
	if role == "" || strings.EqualFold(role, tenantOwnerRole) {
		return nil
	}
	var tmpl *DefaultRole
	for i := range s.opts.DefaultRoles {
		if canonicalizeTenantRole(s.opts.DefaultRoles[i].Name) == role {
			tmpl = &s.opts.DefaultRoles[i]
			break
		}
	}
	if tmpl == nil {
		return nil // not an app default role; nothing to materialize
	}
	// Already materialized?
	var exists bool
	if err := s.pg.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM profiles.tenant_role_permissions WHERE tenant_id=$1::uuid AND role=$2)`, tenantID, role).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	if _, err := s.pg.Exec(ctx, `INSERT INTO profiles.tenant_roles (tenant_id, role) VALUES ($1::uuid,$2) ON CONFLICT (tenant_id, role) DO NOTHING`, tenantID, role); err != nil {
		return err
	}
	for _, p := range dedupeStrings(tmpl.Permissions) {
		if _, err := s.pg.Exec(ctx, `INSERT INTO profiles.tenant_role_permissions (tenant_id, role, permission) VALUES ($1::uuid,$2,$3) ON CONFLICT DO NOTHING`, tenantID, role, p); err != nil {
			return err
		}
	}
	return nil
}
