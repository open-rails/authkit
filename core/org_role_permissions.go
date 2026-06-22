package core

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/open-rails/authkit/authbase"
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
	// globs. Defined in authbase (core-free) and re-exported here.
	PermWildcard = authbase.PermWildcard

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
// The authz-critical matcher is defined in authbase (core-free) and aliased here
// so core's internal callers are unchanged.
var permMatches = authbase.PermMatches

// permNamespace returns the namespace segment (segment 0) of a permission name or
// grant glob — "org" for "org:members:read", "merchant" for "merchant:*". Returns
// "" when there is no namespace prefix.
func permNamespace(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.IndexByte(name, ':'); i > 0 {
		return name[:i]
	}
	return ""
}

// Permissions returns the full permission set: authkit base permissions plus
// the app-declared permissions (deduped, base wins on collision).
// Deprecated: use s.Roles().Permissions.
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

func permissionCoverTokens(perm string) []string {
	perm = strings.TrimSpace(perm)
	if perm == "" || perm == PermWildcard {
		return nil
	}
	parts := strings.Split(perm, ":")
	out := []string{perm}
	seen := map[string]bool{perm: true}
	if len(parts) > 1 && parts[0] != "" && parts[0] != PermWildcard {
		nsGlob := parts[0] + ":" + PermWildcard
		out = append(out, nsGlob)
		seen[nsGlob] = true
	}
	if len(parts) > 2 && parts[0] != "" && parts[0] != PermWildcard {
		// Generate every same-length namespace-anchored glob that could match
		// this concrete permission. Usually this is four strings total for the
		// common ns:resource:action shape.
		max := 1 << (len(parts) - 1)
		for mask := 1; mask < max; mask++ {
			candidate := append([]string(nil), parts...)
			for i := 1; i < len(candidate); i++ {
				if mask&(1<<(i-1)) != 0 {
					candidate[i] = PermWildcard
				}
			}
			tok := strings.Join(candidate, ":")
			if !seen[tok] {
				out = append(out, tok)
				seen[tok] = true
			}
		}
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

// OrgRoleExists reports whether role is defined in the org. Used by the API-key
// mint path to return a precise "unknown_role" error before relying on the DB FK.
// Deprecated: use s.Roles().OrgRoleExists.
func (s *Service) OrgRoleExists(ctx context.Context, orgSlug, role string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return false, err
	}
	return s.q.OrgRoleExists(ctx, db.OrgRoleExistsParams{OrgID: org.ID, Role: canonicalizeOrgRole(role)})
}

// GetRolePermissions returns a role's RAW permission tokens (literals and
// namespace-anchored globs such as `org:*`).
// Deprecated: use s.Roles().GetRolePermissions.
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
// Deprecated: use s.Roles().SetRolePermissions.
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
// Deprecated: use s.Roles().EffectivePermissions.
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
// Deprecated: use s.Roles().EffectiveRolePermissions.
func (s *Service) EffectiveRolePermissions(ctx context.Context, orgSlug, role string) ([]string, error) {
	toks, err := s.GetRolePermissions(ctx, orgSlug, role)
	if err != nil {
		return nil, err
	}
	return sortedKeys(effectivePermsForTokens(toks, s.knownPermissions())), nil
}

// HasPermission reports whether the user holds perm in the org.
//
// MEMOIZED (#95): the user's RAW org grant tokens are resolved ONCE per request
// (single indexed JOIN, rename-aware) and cached on the request-scoped context;
// the perm is then matched against the cached tokens in-memory with the SAME
// namespace-anchored glob semantics the SQL cover-token match used. So a handler
// checking N perms in one request issues exactly ONE org-layer query, not N. The
// allow/deny result is identical to the previous per-check OrgUserHasPermissionToken
// query (a stored token covers perm iff it is one of permissionCoverTokens(perm),
// i.e. permMatches(token, perm)).
// Deprecated: use s.Roles().HasPermission.
func (s *Service) HasPermission(ctx context.Context, orgSlug, userID, perm string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	if strings.TrimSpace(perm) == "" || strings.TrimSpace(orgSlug) == "" || strings.TrimSpace(userID) == "" {
		return false, nil
	}
	tokens, err := s.resolveOrgTokens(ctx, orgSlug, userID)
	if err != nil {
		return false, err
	}
	return tokensCover(tokens, perm), nil
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
// Deprecated: use s.Roles().ValidateGrant.
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

// ownerGrantTokens returns the namespace-anchored apex grants seeded onto the
// prebuilt `owner` role for THIS app's catalog: OrgOwnerGrant (`org:*` — authkit's
// base resources plus every host `org:` perm) PLUS one `<ns>:*` glob for each
// additional non-`platform:` namespace the embedding app declares in
// Config.Permissions. Because the owner owns the org, it owns everything scoped to
// the org, including app-defined resource namespaces (OpenRails `merchant:*`;
// TensorHub `endpoint:*` / `repo:*` / `dataset:*`; #101). The `platform:` layer is
// separate and no org role can reach it, so platform-namespaced app perms are
// never seeded onto the owner. Order is deterministic: `org:*` first, then the app
// namespaces sorted.
//
// Gated by Options.OwnerOwnsAppResources: when false (default) the owner apex is
// exactly `org:*`, so AuthKit imposes no app-ownership policy (#95 contract); apps
// that want the org owner to own their resource namespaces opt in (#100).
func (s *Service) ownerGrantTokens() []string {
	if !s.opts.OwnerOwnsAppResources {
		return []string{OrgOwnerGrant}
	}
	orgNS := permNamespace(OrgOwnerGrant)                 // "org"
	platformNS := permNamespace(platformPermissionPrefix) // "platform"
	seen := map[string]bool{orgNS: true}
	extra := []string{}
	for _, d := range s.opts.Permissions {
		ns := permNamespace(d.Name)
		if ns == "" || ns == platformNS || seen[ns] {
			continue
		}
		seen[ns] = true
		extra = append(extra, ns+":"+PermWildcard)
	}
	sort.Strings(extra)
	return append([]string{OrgOwnerGrant}, extra...)
}

// seedOwnerGrants inserts every ownerGrantTokens() apex grant onto the org's
// prebuilt owner role using q (the base or a tx-scoped *db.Queries). Idempotent:
// OrgRolePermissionInsert is ON CONFLICT DO NOTHING, so re-seeding only adds the
// namespace globs the owner is missing.
func (s *Service) seedOwnerGrants(ctx context.Context, q *db.Queries, orgID string) error {
	for _, tok := range s.ownerGrantTokens() {
		if err := q.OrgRolePermissionInsert(ctx, db.OrgRolePermissionInsertParams{OrgID: orgID, Role: orgOwnerRole, Permission: tok}); err != nil {
			return err
		}
	}
	return nil
}

// EnsureOwnerGrants reconciles an EXISTING org's prebuilt owner role to hold every
// current owner apex grant (`org:*` plus each app-declared resource-namespace
// glob). Additive and idempotent — it never removes a grant. Apps call this after
// declaring a new resource namespace so owners of orgs created BEFORE the
// declaration gain the new `<ns>:*` coverage. (#101)
// Deprecated: use s.Roles().EnsureOwnerGrants.
func (s *Service) EnsureOwnerGrants(ctx context.Context, orgSlug string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return err
	}
	return s.seedOwnerGrants(ctx, s.q, org.ID)
}

// seedRolePermissionDefaults seeds the built-in owner role's apex grants (`org:*`
// plus each app resource namespace, see ownerGrantTokens, #95/#101) for a freshly
// created (or claimed) org. App-declared DefaultRoles are NOT seeded eagerly —
// they are role TEMPLATES for human teammates and are materialized LAZILY the
// first time the role is granted (see materializeDefaultRole), so a solo org
// carries no dormant app-role scaffolding. Idempotent.
func (s *Service) seedRolePermissionDefaults(ctx context.Context, orgID string) error {
	return s.seedOwnerGrants(ctx, s.q, orgID)
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

// PermissionTokenCovers reports whether a stored grant token covers a requested
// permission token. Defined in authbase (core-free) and re-exported here.
var PermissionTokenCovers = authbase.PermissionTokenCovers

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
