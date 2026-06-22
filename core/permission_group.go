package core

// Permission-group model (#111): the generalization of "org" into an N-level,
// resource-scoped RBAC tree. A permission-group is a typed container that holds
// role assignments and has a SINGLE parent; a permission check walks the parent
// chain to the root and unions the subject's assignments across it.
//
// This file is the pure-logic FOUNDATION — the declared type system + its
// validation — with no database or service dependency. The schema (catalogs,
// containment, management profiles) an app declares is validated here once at
// construction; the engine (group lifecycle, Can() walk-up) builds on it.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/open-rails/authkit/authbase"
)

const (
	// RootType is the single built-in permission-group type (the former
	// "platform" layer, #95). Every deployment has exactly ONE root group: the
	// parentless ancestor of every other group. Its namespace is `root:`.
	RootType = "root"

	// OwnerRoleName is the required role every type ships. It holds the type's
	// WHOLE namespace (`<type>:*`) and nothing else — never a bare `*`, never
	// another persona. Widest reach within the type, still namespace-pure.
	OwnerRoleName = "owner"

	// MemberRoleName is the base-membership role authkit seeds on every group.
	// Minimal authority (no perms unless the app's catalog gives it some).
	MemberRoleName = "member"
)

// segmentRe matches ONE lowercase permission segment (persona, resource, or
// action): a letter followed by letters/digits/hyphens.
var segmentRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// ValidatePermission checks a CONCRETE catalog permission: EXACTLY three
// lowercase segments `<persona>:<resource>:<action>` (e.g. `merchant:catalog:update`,
// `root:users:ban`). Two-part (`repo:update`) and four-part perms are rejected —
// a two-part perm must grow a resource (`repo:contents:update`); a type may use
// a `:self:` resource for "the thing itself" actions (`endpoint:self:invoke`).
func ValidatePermission(p string) error {
	segs := strings.Split(p, ":")
	if len(segs) != 3 {
		return fmt.Errorf("permission %q must be exactly three segments <persona>:<resource>:<action>", p)
	}
	for _, s := range segs {
		if !segmentRe.MatchString(s) {
			return fmt.Errorf("permission %q: segment %q must match [a-z][a-z0-9-]*", p, s)
		}
	}
	return nil
}

// ValidateGrantPattern checks a GRANT token (what a role holds). Grants may be
// concrete perms OR namespace-anchored globs, but NEVER a bare `*`:
//
//	<persona>:<resource>:<action>   a concrete perm
//	<persona>:<resource>:*          all actions on a resource
//	<persona>:*                     the whole persona namespace (the owner grant)
//
// The persona segment is always a literal — a bare `*` or `*`-persona is rejected,
// which is what makes reach != capability structural (a `merchant:*` grant can
// never name a `root:`/`customer:` perm). Mirrors authbase.PermMatches semantics
// but is STRICTER: it forbids mid-glob forms like `persona:*:action`.
func ValidateGrantPattern(g string) error {
	if g == "" {
		return fmt.Errorf("empty grant")
	}
	segs := strings.Split(g, ":")
	if !segmentRe.MatchString(segs[0]) {
		return fmt.Errorf("grant %q: persona segment must be a literal lowercase name (no bare *)", g)
	}
	switch len(segs) {
	case 2:
		if segs[1] != authbase.PermWildcard {
			return fmt.Errorf("grant %q: a two-segment grant must be <persona>:*", g)
		}
		return nil
	case 3:
		if !segmentRe.MatchString(segs[1]) {
			return fmt.Errorf("grant %q: resource segment must match [a-z][a-z0-9-]*", g)
		}
		if segs[2] != authbase.PermWildcard && !segmentRe.MatchString(segs[2]) {
			return fmt.Errorf("grant %q: action segment must be a name or *", g)
		}
		return nil
	default:
		return fmt.Errorf("grant %q: must be <persona>:* , <persona>:<resource>:* , or <persona>:<resource>:<action>", g)
	}
}

// PermissionPersona returns a permission/grant's first segment (its persona ≡
// type ≡ namespace). PermissionPersona("merchant:catalog:update") == "merchant".
func PermissionPersona(perm string) string {
	if i := strings.IndexByte(perm, ':'); i >= 0 {
		return perm[:i]
	}
	return perm
}

// OwnerGrant is the namespace-pure owner grant for a type: `<type>:*`. Never a
// bare `*`. The owner role of every type holds exactly this.
func OwnerGrant(typeName string) string {
	return typeName + ":" + authbase.PermWildcard
}

// RoleDef is a named permission bundle within a type's catalog. Its permissions
// are grant patterns, all in the OWNING type's persona (namespace-pure).
type RoleDef struct {
	Name        string
	Permissions []string
}

// ManagementProfile chooses which group-management operations authkit exposes as
// AUTO-GENERATED routes for a type's groups (the `api-routes.*` block). Each flag
// gates ROUTE GENERATION, not the capability: the host can always do the op via
// core even with the route off (false ⇒ no public route / 404, not "impossible").
type ManagementProfile struct {
	MemberAssignment      bool // api-routes.member-assignment
	CustomRoleCreation    bool // api-routes.custom-role-creation (requires AllowCustomRoles)
	APIKeyMinting         bool // api-routes.api-key-minting
	RemoteAppRegistration bool // api-routes.remote-app-registration
	Invitation            bool // api-routes.invitation
}

// GroupTypeDef declares one permission-group type (a persona). persona ≡ type ≡
// the first permission segment. `Name == RootType` is the parentless singleton.
type GroupTypeDef struct {
	Name             string
	Roles            []RoleDef // app-declared; owner (=<type>:*) + member are injected if absent
	AllowedParents   []string  // declared types; empty ⇒ root (parentless). Non-root needs >=1.
	AllowCustomRoles bool      // may a group owner define ADDITIONAL custom roles?
	Routes           ManagementProfile
}

// GroupSchema is the validated, immutable set of declared group types — the
// containment schema + catalogs + management profiles. Construct via
// NewGroupSchema, which validates everything once.
type GroupSchema struct {
	types map[string]GroupTypeDef // effective defs (owner/member injected, roles deduped)
	order []string                // type names, sorted
}

// NewGroupSchema validates an app's declared types and returns the schema, or an
// error describing the first problem. It enforces: a single root type (named
// RootType, parentless); every type has an `owner` role == `<type>:*`; every
// role grant is a valid pattern in the type's OWN persona (namespace purity);
// allowed-parent edges reference declared types and form an acyclic tree rooted
// at root; and CustomRoleCreation routes imply AllowCustomRoles.
func NewGroupSchema(types ...GroupTypeDef) (*GroupSchema, error) {
	s := &GroupSchema{types: make(map[string]GroupTypeDef, len(types))}
	for _, t := range types {
		if !segmentRe.MatchString(t.Name) {
			return nil, fmt.Errorf("group type %q: name must match [a-z][a-z0-9-]*", t.Name)
		}
		if _, dup := s.types[t.Name]; dup {
			return nil, fmt.Errorf("group type %q declared twice", t.Name)
		}
		eff, err := normalizeType(t)
		if err != nil {
			return nil, err
		}
		s.types[t.Name] = eff
	}

	root, err := s.validateRoot()
	if err != nil {
		return nil, err
	}
	_ = root

	if err := s.validateContainment(); err != nil {
		return nil, err
	}

	for name := range s.types {
		s.order = append(s.order, name)
	}
	sort.Strings(s.order)
	return s, nil
}

// normalizeType validates a declared type and injects the seeded owner/member
// roles, returning the effective definition stored in the schema.
func normalizeType(t GroupTypeDef) (GroupTypeDef, error) {
	if t.Routes.CustomRoleCreation && !t.AllowCustomRoles {
		return t, fmt.Errorf("group type %q: api-routes.custom-role-creation requires AllowCustomRoles", t.Name)
	}

	byName := make(map[string]RoleDef, len(t.Roles)+2)
	order := make([]string, 0, len(t.Roles)+2)
	add := func(r RoleDef) {
		if _, ok := byName[r.Name]; !ok {
			order = append(order, r.Name)
		}
		byName[r.Name] = r
	}

	for _, r := range t.Roles {
		if r.Name == "" {
			return t, fmt.Errorf("group type %q: a role has an empty name", t.Name)
		}
		if _, dup := byName[r.Name]; dup {
			return t, fmt.Errorf("group type %q: role %q declared twice", t.Name, r.Name)
		}
		for _, g := range r.Permissions {
			if err := ValidateGrantPattern(g); err != nil {
				return t, fmt.Errorf("group type %q role %q: %w", t.Name, r.Name, err)
			}
			if PermissionPersona(g) != t.Name {
				return t, fmt.Errorf("group type %q role %q: grant %q is cross-persona — a %q role may hold only %q: perms", t.Name, r.Name, g, t.Name, t.Name)
			}
		}
		add(r)
	}

	// Seed owner = <type>:* (required; namespace-pure). If declared, it must match.
	want := OwnerGrant(t.Name)
	if owner, ok := byName[OwnerRoleName]; ok {
		if len(owner.Permissions) != 1 || owner.Permissions[0] != want {
			return t, fmt.Errorf("group type %q: the %q role must hold exactly [%q]", t.Name, OwnerRoleName, want)
		}
	} else {
		add(RoleDef{Name: OwnerRoleName, Permissions: []string{want}})
	}
	// Seed member (base membership; minimal) if absent.
	if _, ok := byName[MemberRoleName]; !ok {
		add(RoleDef{Name: MemberRoleName})
	}

	eff := t
	eff.Roles = make([]RoleDef, 0, len(order))
	for _, n := range order {
		eff.Roles = append(eff.Roles, byName[n])
	}
	return eff, nil
}

// validateRoot enforces exactly one parentless type, named RootType.
func (s *GroupSchema) validateRoot() (string, error) {
	var roots []string
	for name, t := range s.types {
		if len(t.AllowedParents) == 0 {
			roots = append(roots, name)
		}
	}
	switch len(roots) {
	case 0:
		return "", fmt.Errorf("no root type declared (exactly one parentless type, named %q, is required)", RootType)
	case 1:
		if roots[0] != RootType {
			return "", fmt.Errorf("the parentless type must be named %q, got %q", RootType, roots[0])
		}
		return roots[0], nil
	default:
		sort.Strings(roots)
		return "", fmt.Errorf("exactly one root (parentless) type is allowed; found %v", roots)
	}
}

// validateContainment checks every allowed-parent edge references a declared
// type and that the child→parent graph is acyclic (so every type reaches root).
func (s *GroupSchema) validateContainment() error {
	for name, t := range s.types {
		if name == RootType {
			continue
		}
		seen := map[string]bool{}
		for _, p := range t.AllowedParents {
			if _, ok := s.types[p]; !ok {
				return fmt.Errorf("group type %q: allowed parent %q is not a declared type", name, p)
			}
			if seen[p] {
				return fmt.Errorf("group type %q: allowed parent %q listed twice", name, p)
			}
			seen[p] = true
		}
	}
	// Cycle detection over child → allowedParents edges (root is the only sink).
	const (
		white = 0
		grey  = 1
		black = 2
	)
	color := make(map[string]int, len(s.types))
	var visit func(string, []string) error
	visit = func(n string, stack []string) error {
		color[n] = grey
		for _, p := range s.types[n].AllowedParents {
			switch color[p] {
			case grey:
				return fmt.Errorf("containment cycle: %s -> %s", strings.Join(append(stack, n, p), " -> "), p)
			case white:
				if err := visit(p, append(stack, n)); err != nil {
					return err
				}
			}
		}
		color[n] = black
		return nil
	}
	for name := range s.types {
		if color[name] == white {
			if err := visit(name, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

// Type returns a declared type's effective definition.
func (s *GroupSchema) Type(name string) (GroupTypeDef, bool) {
	t, ok := s.types[name]
	return t, ok
}

// Types returns the declared type names, sorted.
func (s *GroupSchema) Types() []string {
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}

// IsRoot reports whether name is the root type.
func (s *GroupSchema) IsRoot(name string) bool { return name == RootType }

// Roles returns a type's effective roles (app-declared + seeded owner/member).
func (s *GroupSchema) Roles(typeName string) ([]RoleDef, bool) {
	t, ok := s.types[typeName]
	if !ok {
		return nil, false
	}
	out := make([]RoleDef, len(t.Roles))
	copy(out, t.Roles)
	return out, true
}

// Role returns a single role from a type's catalog.
func (s *GroupSchema) Role(typeName, roleName string) (RoleDef, bool) {
	t, ok := s.types[typeName]
	if !ok {
		return RoleDef{}, false
	}
	for _, r := range t.Roles {
		if r.Name == roleName {
			return r, true
		}
	}
	return RoleDef{}, false
}

// ValidateParent enforces the containment schema at INSTANCE-create time: a
// proposed (childType, parentType) edge. root is parentless; every non-root
// group needs a parent whose type is in the child type's AllowedParents — so
// e.g. `root -> repo` is structurally impossible, not merely discouraged.
func (s *GroupSchema) ValidateParent(childType, parentType string) error {
	ct, ok := s.types[childType]
	if !ok {
		return fmt.Errorf("unknown group type %q", childType)
	}
	if childType == RootType {
		if parentType != "" {
			return fmt.Errorf("the root group is parentless; got parent type %q", parentType)
		}
		return nil
	}
	if parentType == "" {
		return fmt.Errorf("a %q group requires a parent of type %v", childType, ct.AllowedParents)
	}
	if _, ok := s.types[parentType]; !ok {
		return fmt.Errorf("unknown parent group type %q", parentType)
	}
	for _, ap := range ct.AllowedParents {
		if ap == parentType {
			return nil
		}
	}
	return fmt.Errorf("a %q group must have a parent of type %v, got %q", childType, ct.AllowedParents, parentType)
}
