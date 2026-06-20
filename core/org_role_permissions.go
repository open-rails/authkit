package core

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/open-rails/authkit/internal/db"
)

// Org RBAC (authkit #46/#95): roles are NAMES (profiles.org_roles) plus a set of
// permission strings (profiles.org_role_permissions). Permissions are OPAQUE to
// authkit — the embedding app declares its catalog and authkit adds a base set;
// authkit only stores / serves / validates set-membership, never meaning.
//
// Permission grammar (#95): `<namespace>:<resource>:<action>`, lowercase, three
// colon-separated segments. Actions are CRUD (`create`/`read`/`update`/`delete`).
// GRANT tokens may be namespace-anchored GLOBS — `org:*`, `org:members:*`,
// `org:*:read` — where `*` is a wildcard for a whole segment. A BARE standalone
// `*` is REJECTED (globs must carry a namespace prefix). There is NO negation
// (the `!perm` exclusion operator was removed in #93 — positive grants only).

const (
	// PermWildcard is the wildcard CHARACTER used inside namespace-anchored
	// globs (`org:*`, `org:members:*`, `org:*:read`, `platform:*`). A bare
	// standalone `*` is NOT a valid grant — it is rejected everywhere.
	PermWildcard = "*"

	// reservedPermissionPrefix is the namespace authkit owns for its base
	// org-management permissions; app catalogs must not declare under it, and
	// API keys may not be scoped to its write actions.
	reservedPermissionPrefix = "org:"

	// authkit base org-management permissions, granular CRUD per resource
	// (#95). They gate authkit's own org-management endpoints. Old coarse
	// `org:<resource>:manage` + `org:read` were RETIRED in favor of these
	// concrete actions plus globs (`org:members:*`, `org:*:read`).
	PermOrgMembersCreate = "org:members:create" // add a member
	PermOrgMembersRead   = "org:members:read"   // list members + their roles
	PermOrgMembersUpdate = "org:members:update" // change a member's roles
	PermOrgMembersDelete = "org:members:delete" // remove a member

	PermOrgRolesCreate = "org:roles:create" // define a role
	PermOrgRolesRead   = "org:roles:read"   // list roles + their perms
	PermOrgRolesUpdate = "org:roles:update" // set perms / rename a role
	PermOrgRolesDelete = "org:roles:delete" // delete a role

	PermOrgAPIKeysCreate = "org:api_keys:create" // mint an API key
	PermOrgAPIKeysRead   = "org:api_keys:read"   // list API-key metadata (NEVER the secret)
	PermOrgAPIKeysDelete = "org:api_keys:delete" // revoke an API key (no update — immutable; rotate = create+delete)

	PermOrgRemoteAppsCreate = "org:remote_applications:create" // register an org-owned remote application
	PermOrgRemoteAppsRead   = "org:remote_applications:read"   // list + detail
	PermOrgRemoteAppsUpdate = "org:remote_applications:update" // edit config / origins / memberships
	PermOrgRemoteAppsDelete = "org:remote_applications:delete" // delete

	PermOrgSettingsRead   = "org:settings:read"   // read the org's own name/profile (GET /orgs/{org})
	PermOrgSettingsUpdate = "org:settings:update" // rename / edit metadata (POST /orgs/{org}/rename)

	// OrgOwnerGrant is the apex grant held by the prebuilt `owner` role: every
	// permission in the `org:` namespace for that ONE org (#95 — tightened from
	// a bare `*`). It covers AuthKit's base resources AND every host-declared
	// `org:<resource>` perm in a single grant, but can NEVER reach the separate
	// `platform:` layer.
	OrgOwnerGrant = "org:*"
)

// ErrUnknownPermission indicates a permission not present in the catalog.
var ErrUnknownPermission = errors.New("unknown_permission")

// BasePermissions are the org-management permissions authkit defines for every
// embedding app (reserved `org:` namespace), granular CRUD per resource (#95).
func BasePermissions() []PermissionDef {
	return []PermissionDef{
		{Name: PermOrgMembersCreate, Description: "Add an org member"},
		{Name: PermOrgMembersRead, Description: "List org members and their roles"},
		{Name: PermOrgMembersUpdate, Description: "Change an org member's roles"},
		{Name: PermOrgMembersDelete, Description: "Remove an org member"},

		{Name: PermOrgRolesCreate, Description: "Define an org role"},
		{Name: PermOrgRolesRead, Description: "List org roles and their permissions"},
		{Name: PermOrgRolesUpdate, Description: "Set permissions on / rename an org role"},
		{Name: PermOrgRolesDelete, Description: "Delete an org role"},

		{Name: PermOrgAPIKeysCreate, Description: "Mint an API key"},
		{Name: PermOrgAPIKeysRead, Description: "List API-key metadata (never the secret)"},
		{Name: PermOrgAPIKeysDelete, Description: "Revoke an API key"},

		{Name: PermOrgRemoteAppsCreate, Description: "Register an org-owned remote application"},
		{Name: PermOrgRemoteAppsRead, Description: "List and inspect org-owned remote applications"},
		{Name: PermOrgRemoteAppsUpdate, Description: "Edit an org-owned remote application"},
		{Name: PermOrgRemoteAppsDelete, Description: "Delete an org-owned remote application"},

		{Name: PermOrgSettingsRead, Description: "Read the org's own name and profile"},
		{Name: PermOrgSettingsUpdate, Description: "Rename and edit the org's own metadata"},
	}
}

// IsReservedPermission reports whether name is in authkit's reserved base
// namespace (an app catalog may not redefine the base resource names; API keys
// may not hold the write actions, see IsAPIKeyGrantableReservedPermission).
func IsReservedPermission(name string) bool {
	return strings.HasPrefix(strings.TrimSpace(name), reservedPermissionPrefix)
}

// IsAPIKeyGrantableReservedPermission reports whether a reserved `org:`
// permission may be granted to an API key. Only READ actions qualify: an API
// key can never hold a write/manage perm, so it can never mint another API key,
// redefine roles, or alter membership — read-only automation (monitoring/audit
// bots) is the only escalation-harmless case. Accepts literals (`org:roles:read`)
// and read globs (`org:*:read`). Returns false for non-reserved names.
func IsAPIKeyGrantableReservedPermission(name string) bool {
	name = strings.TrimSpace(name)
	if !IsReservedPermission(name) {
		return false
	}
	return strings.HasSuffix(name, ":read")
}

// permMatches reports whether a GRANT token authorizes a CONCRETE permission.
// The grant may be a literal (`org:members:read`) or a namespace-anchored glob
// where `*` wildcards a whole segment (`org:members:*`, `org:*:read`, `org:*`).
// The namespace (segment 0) must be a literal — a bare `*` (or a `*` namespace)
// never matches. A two-segment glob `ns:*` matches every concrete `ns:…` perm.
func permMatches(grant, concrete string) bool {
	grant = strings.TrimSpace(grant)
	concrete = strings.TrimSpace(concrete)
	if grant == "" || grant == PermWildcard {
		return false // bare "*" is not a valid grant — it never matches
	}
	g := strings.Split(grant, ":")
	c := strings.Split(concrete, ":")
	if g[0] == "" || g[0] == PermWildcard {
		return false // namespace must be a literal prefix (namespace-anchored)
	}
	// Two-segment namespace-wide glob: `ns:*` covers every `ns:<resource>:<action>`.
	if len(g) == 2 && g[1] == PermWildcard {
		return len(c) >= 1 && c[0] == g[0]
	}
	if len(g) != len(c) {
		return false
	}
	for i := range g {
		if i == 0 {
			if g[i] != c[i] {
				return false
			}
			continue
		}
		if g[i] != PermWildcard && g[i] != c[i] {
			return false
		}
	}
	return true
}

// Permissions returns the full permission set: authkit base permissions plus
// the app-declared permissions (deduped, base wins on collision).
func (s *Service) Permissions() []PermissionDef {
	out := append([]PermissionDef{}, BasePermissions()...)
	seen := map[string]bool{}
	for _, d := range out {
		seen[d.Name] = true
	}
	for _, d := range s.opts.Permissions {
		n := strings.TrimSpace(d.Name)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, PermissionDef{Name: n, Description: d.Description})
	}
	return out
}

func (s *Service) knownPermissions() map[string]bool {
	m := map[string]bool{}
	for _, d := range s.Permissions() {
		m[d.Name] = true
	}
	return m
}

// effectivePermsForTokens expands one role's stored grant tokens against the
// catalog into the set of CONCRETE permissions it confers: every catalog perm
// matched by a literal or glob token (#95). A bare `*` and any token matching
// nothing in the catalog are dropped. No negation (#93).
func effectivePermsForTokens(tokens []string, catalog map[string]bool) map[string]bool {
	out := map[string]bool{}
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" || t == PermWildcard || strings.HasPrefix(t, "!") {
			continue // invalid grant token — never expand it
		}
		if strings.Contains(t, PermWildcard) {
			// Namespace-anchored glob: expand against the catalog — only
			// concrete catalog perms can match a glob (`org:*` → every `org:` perm).
			for p := range catalog {
				if permMatches(t, p) {
					out[p] = true
				}
			}
			continue
		}
		// Literal grant: the principal holds exactly this permission. The
		// catalog gates grants at WRITE time (ValidateGrant); at read time a
		// stored literal is honored as-is (incl. host perms + directly-seeded
		// machine grants), never silently dropped.
		out[t] = true
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

// GetRolePermissions returns a role's RAW permission tokens (literals and
// namespace-anchored globs such as `org:*`).
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
	catalog := s.knownPermissions()
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
// the catalog (globs included). Used to enforce no-escalation when assigning a
// role to a member (the assigner must hold everything the role grants).
func (s *Service) EffectiveRolePermissions(ctx context.Context, orgSlug, role string) ([]string, error) {
	toks, err := s.GetRolePermissions(ctx, orgSlug, role)
	if err != nil {
		return nil, err
	}
	return sortedKeys(effectivePermsForTokens(toks, s.knownPermissions())), nil
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
// role (#94 no-escalation, #95 glob model). Each token must EXPAND to at least
// one catalog permission (else returned in unknown — a bare `*`, a typo, or a
// glob matching nothing is invalid). No-escalation: the actor must already hold
// EVERY concrete permission the token expands to (else the token is returned in
// offending) — so granting `org:members:*` requires holding all of
// `org:members:*`. `actorAll` short-circuits the no-escalation check for an
// actor known to hold everything (bootstrap system-actor / platform admin).
// Returns (unknown, offending).
func (s *Service) ValidateGrant(ctx context.Context, orgSlug, actorUserID string, tokens []string, actorAll bool) (unknown, offending []string, err error) {
	catalog := s.knownPermissions()
	var actorEff map[string]bool
	if !actorAll {
		eff, e := s.EffectivePermissions(ctx, orgSlug, actorUserID)
		if e != nil {
			return nil, nil, e
		}
		actorEff = map[string]bool{}
		for _, p := range eff {
			actorEff[p] = true
		}
	}
	for _, t := range dedupeStrings(tokens) {
		if t == PermWildcard || strings.HasPrefix(t, "!") {
			unknown = append(unknown, t) // invalid grant token
			continue
		}
		// Expand the token against the catalog. A literal hits itself; a glob
		// hits every matching concrete perm.
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
		// No-escalation: the actor must hold every concrete perm this token confers.
		for _, p := range expansion {
			if !actorEff[p] {
				offending = append(offending, t)
				break
			}
		}
	}
	return unknown, offending, nil
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

// seedRolePermissionDefaults seeds the built-in owner role permission (`org:*`,
// #95) for a freshly created (or claimed) org. App-declared DefaultRoles are NOT
// seeded eagerly — they are role TEMPLATES for human teammates and are
// materialized LAZILY the first time the role is granted (see
// materializeDefaultRole), so a solo org carries no dormant app-role
// scaffolding. Idempotent.
func (s *Service) seedRolePermissionDefaults(ctx context.Context, orgID string) error {
	return s.q.OrgRolePermissionInsert(ctx, db.OrgRolePermissionInsertParams{OrgID: orgID, Role: orgOwnerRole, Permission: OrgOwnerGrant})
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

// EffectivePermsForTokens is the EXPORTED token evaluator: it expands one role's
// stored grant tokens against a catalog exactly the way authkit resolves
// permissions at request time (literals + namespace-anchored globs; no negation,
// no bare `*`; #93/#95).
//
// Hosts should use THIS function in security tests that lock their seeded role
// definitions, instead of replicating the semantics: a replicated evaluator
// drifts, and drift in permission semantics fails silently.
func EffectivePermsForTokens(tokens []string, catalog map[string]bool) map[string]bool {
	return effectivePermsForTokens(tokens, catalog)
}

// UnknownRoleTokenNames returns every grant token that expands to NOTHING in the
// catalog (a bare `*`, a typo'd literal, or a glob matching no catalog perm) —
// validate seeds with this at startup or in tests and treat a non-empty result
// as a hard error so a role never references a permission that doesn't exist.
func UnknownRoleTokenNames(tokens []string, catalog map[string]bool) []string {
	var unknown []string
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if t == PermWildcard || strings.HasPrefix(t, "!") {
			unknown = append(unknown, t)
			continue
		}
		matched := false
		for p := range catalog {
			if permMatches(t, p) {
				matched = true
				break
			}
		}
		if !matched {
			unknown = append(unknown, t)
		}
	}
	return unknown
}

// BaseReservedPermissions lists authkit's own reserved base permissions — the
// concrete names hosts must include in the catalog they validate seeds against.
func BaseReservedPermissions() []string {
	out := make([]string, 0, len(BasePermissions()))
	for _, d := range BasePermissions() {
		out = append(out, d.Name)
	}
	return out
}
