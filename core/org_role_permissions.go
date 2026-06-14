package core

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/open-rails/authkit/internal/db"
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
	// service tokens may not be scoped to them.
	reservedPermissionPrefix = "org:"

	// authkit base org-management permissions. They gate authkit's own
	// org-management endpoints via the permission system.
	PermOrgRolesManage   = "org:roles:manage"          // create/modify/delete roles + set role permissions
	PermOrgMembersManage = "org:members:manage"        // add/remove members + grant/remove their roles
	PermOrgTokensManage  = "org:service_tokens:manage" // mint/revoke service tokens
	PermOrgRead          = "org:read"                  // view members/roles/tokens
)

// ErrUnknownPermission indicates a permission not present in the catalog.
var ErrUnknownPermission = errors.New("unknown_permission")

// BasePermissions are the org-management permissions authkit defines for every
// embedding app (reserved `org:` namespace).
func BasePermissions() []PermissionDef {
	return []PermissionDef{
		{Name: PermOrgRolesManage, Description: "Create, modify, and delete org roles and their permissions"},
		{Name: PermOrgMembersManage, Description: "Add/remove org members and grant or remove their roles"},
		{Name: PermOrgTokensManage, Description: "Mint and revoke service tokens (service tokens)"},
		{Name: PermOrgRead, Description: "View org members, roles, and service tokens"},
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
// (org:roles:manage, org:members:manage, org:service_tokens:manage) stay user-only so
// a service token can never bootstrap broader authority — it cannot mint another service token,
// redefine roles, or alter membership. org:read is escalation-harmless and
// unblocks read-only automation (monitoring/audit bots listing members/roles).
var serviceTokenGrantableReservedPermissions = map[string]bool{
	PermOrgRead: true,
}

// IsServiceTokenGrantableReservedPermission reports whether a reserved `org:` permission
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
func (s *Service) GetRolePermissions(ctx context.Context, orgSlug, role string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return nil, err
	}
	role = canonicalizeOrgRole(role)
	return s.q.OrgRolePermissions(ctx, db.OrgRolePermissionsParams{OrgID: org.ID, Role: role})
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
	exists, err := s.q.OrgRoleExists(ctx, db.OrgRoleExistsParams{OrgID: org.ID, Role: role})
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
	if err := qtx.OrgRolePermissionsDelete(ctx, db.OrgRolePermissionsDeleteParams{OrgID: org.ID, Role: role}); err != nil {
		return err
	}
	for _, p := range clean {
		if err := qtx.OrgRolePermissionInsert(ctx, db.OrgRolePermissionInsertParams{OrgID: org.ID, Role: role, Permission: p}); err != nil {
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
			// A concrete permission is valid if it is in the catalog, OR it is
			// a RESOURCE-SCOPED grant "<resource>:<action>:<name>" whose
			// "<resource>:<action>" base is in the catalog (e.g. repo:write:my-model
			// validates against repo:write). The app interprets the <name>;
			// authkit only checks the base is a real permission. Reserved
			// 3-segment base perms (org:roles:manage, ...) match catalog[t]
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
			// org-wide base (holding repo:write lets you grant repo:write:x).
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
// a freshly created (or claimed) org. App-declared DefaultRoles are NOT
// seeded eagerly — they are role TEMPLATES for human teammates and are
// materialized LAZILY the first time the role is granted (see
// materializeDefaultRole), so a solo org carries no dormant app-role
// scaffolding. Idempotent.
func (s *Service) seedRolePermissionDefaults(ctx context.Context, orgID string) error {
	return s.q.OrgRolePermissionInsert(ctx, db.OrgRolePermissionInsertParams{OrgID: orgID, Role: orgOwnerRole, Permission: PermWildcard})
}

// materializeDefaultRole lazily seeds an app-declared DefaultRole's permission
// template into the org the first time that role is needed (e.g. on grant), if
// it isn't already present. No-op for the owner role, unknown roles, or roles
// that already have permissions. Idempotent.
func (s *Service) materializeDefaultRole(ctx context.Context, orgID, role string) error {
	role = canonicalizeOrgRole(role)
	if role == "" || strings.EqualFold(role, orgOwnerRole) {
		return nil
	}
	var tmpl *DefaultRole
	for i := range s.opts.DefaultRoles {
		if canonicalizeOrgRole(s.opts.DefaultRoles[i].Name) == role {
			tmpl = &s.opts.DefaultRoles[i]
			break
		}
	}
	if tmpl == nil {
		return nil // not an app default role; nothing to materialize
	}
	// Already materialized?
	exists, err := s.q.OrgRoleHasPermissions(ctx, db.OrgRoleHasPermissionsParams{OrgID: orgID, Role: role})
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	if err := s.q.OrgRoleDefine(ctx, db.OrgRoleDefineParams{OrgID: orgID, Role: role}); err != nil {
		return err
	}
	for _, p := range dedupeStrings(tmpl.Permissions) {
		if err := s.q.OrgRolePermissionInsert(ctx, db.OrgRolePermissionInsertParams{OrgID: orgID, Role: role, Permission: p}); err != nil {
			return err
		}
	}
	return nil
}

// EffectivePermsForTokens is the EXPORTED token evaluator: it expands one
// role's stored tokens against a catalog exactly the way authkit resolves
// permissions at request time (`*` => every catalog permission; `!p` =>
// remove p; otherwise the literal permission).
//
// Hosts should use THIS function in security tests that lock their seeded
// role definitions, instead of replicating the semantics: a replicated
// evaluator drifts, and drift in permission semantics fails silently (the
// 2026-06-10 incident: a host's admin role excluded org-era names that no
// longer matched anything, silently expanding admin to ALL permissions).
func EffectivePermsForTokens(tokens []string, catalog map[string]bool) map[string]bool {
	return effectivePermsForTokens(tokens, catalog)
}

// UnknownRoleTokenNames returns every concrete name referenced by tokens
// (inclusions AND `!p` exclusions) that is absent from catalog. Unknown
// EXCLUSIONS are the dangerous case: they subtract nothing, so a role meant
// to be narrowed silently keeps the permission — validate seeds with this at
// startup or in tests and treat a non-empty result as a hard error.
func UnknownRoleTokenNames(tokens []string, catalog map[string]bool) []string {
	var unknown []string
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" || t == PermWildcard {
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(t, permExcludePrefix))
		if !catalog[name] {
			unknown = append(unknown, t)
		}
	}
	return unknown
}

// BaseReservedPermissions lists authkit's own reserved base permissions —
// the names hosts must include in the catalog they validate seeds against.
func BaseReservedPermissions() []string {
	return []string{PermOrgRolesManage, PermOrgMembersManage, PermOrgTokensManage, PermOrgRead}
}
