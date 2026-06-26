package authcore

// Permission-group model (#111): an N-level, resource-scoped RBAC tree. A
// permission-group is a persona-scoped container that holds
// role assignments and has a SINGLE parent; a permission check walks the parent
// chain to the root and unions the subject's assignments across it.
//
// This file is the pure-logic FOUNDATION — the declared persona schema + its
// validation — with no database or service dependency. The schema (catalogs,
// containment, management profiles) an app declares is validated here once at
// construction; the engine (group lifecycle, Can() walk-up) builds on it.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	authkit "github.com/open-rails/authkit"
)

const (
	// RootPersona is the single built-in permission-group persona. Every deployment has exactly ONE root group: the
	// parentless ancestor of every other group. Its namespace is `root:`.
	RootPersona = "root"

	// OwnerRoleName is the required role every persona ships. It holds the
	// persona's WHOLE namespace (`<persona>:*`) and nothing else — never a bare
	// `*`, never another persona. Widest reach within the persona, still
	// namespace-pure.
	OwnerRoleName = "owner"
)

// segmentRe matches ONE lowercase permission segment (persona, resource, or
// action): a letter followed by letters/digits/hyphens.
var segmentRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
var instanceSlugRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func validateGroupInstanceSlug(persona, slug string) error {
	if persona == RootPersona {
		if slug != "" {
			return fmt.Errorf("root group must not have a resource slug")
		}
		return nil
	}
	if !instanceSlugRe.MatchString(slug) {
		return fmt.Errorf("resource slug %q must be lowercase URL-safe", slug)
	}
	return nil
}

// ValidatePermission checks a CONCRETE catalog permission: EXACTLY three
// lowercase segments `<persona>:<resource>:<action>` (e.g. `merchant:catalog:update`,
// `root:users:ban`). Two-part (`repo:update`) and four-part perms are rejected —
// a two-part perm must grow a resource (`repo:contents:update`); a persona may use
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
// never name a `root:`/`customer:` perm). Mirrors authkit.PermMatches semantics
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
		if segs[1] != authkit.PermWildcard {
			return fmt.Errorf("grant %q: a two-segment grant must be <persona>:*", g)
		}
		return nil
	case 3:
		if !segmentRe.MatchString(segs[1]) {
			return fmt.Errorf("grant %q: resource segment must match [a-z][a-z0-9-]*", g)
		}
		if segs[2] != authkit.PermWildcard && !segmentRe.MatchString(segs[2]) {
			return fmt.Errorf("grant %q: action segment must be a name or *", g)
		}
		return nil
	default:
		return fmt.Errorf("grant %q: must be <persona>:* , <persona>:<resource>:* , or <persona>:<resource>:<action>", g)
	}
}

// PermissionPersona returns a permission/grant's first segment (its persona ≡
// namespace). PermissionPersona("merchant:catalog:update") == "merchant".
func PermissionPersona(perm string) string {
	if i := strings.IndexByte(perm, ':'); i >= 0 {
		return perm[:i]
	}
	return perm
}

// OwnerGrant is the namespace-pure owner grant for a persona: `<persona>:*`.
// Never a bare `*`. The owner role of every persona holds exactly this.
func OwnerGrant(persona string) string {
	return persona + ":" + authkit.PermWildcard
}

// RoleDef is a named permission bundle within a persona's catalog. Its
// permissions are grant patterns, all in the owning persona namespace.
type RoleDef struct {
	Name        string
	Permissions []string
	RequiresMFA bool
}

type PersonaCapabilities = authkit.PersonaCapabilities

// PersonaDef declares one permission-group persona, which is also the first
// permission segment. `Name == RootPersona` is the parentless singleton.
type PersonaDef struct {
	Name         string
	Roles        []RoleDef // app-declared; owner (=<persona>:*) is injected if absent
	Parent       string    // declared persona; empty only for root. Non-root must name exactly one parent.
	Capabilities PersonaCapabilities
	Catalog      []string
	// RequireConsent makes admitting a NEW member to a group of this persona require
	// the invitee's acceptance (#193): an owner/manager cannot silently direct-add an
	// existing user — the add always routes through a consent invite the user accepts.
	// Default false (instant direct-add allowed; what root uses). This is a JOIN-time
	// policy only — it does NOT affect changing or removing an existing member's role.
	RequireConsent bool
}

// GroupSchema is the validated, immutable set of declared group personas — the
// containment schema + catalogs + management profiles. Construct via
// NewGroupSchema, which validates everything once.
type GroupSchema struct {
	types map[string]PersonaDef // effective defs (owner injected, roles deduped)
	order []string              // persona names, sorted
}

// NewGroupSchema validates an app's declared personas and returns the schema, or
// an error describing the first problem. It enforces: a single root persona
// (named RootPersona, parentless); every persona has an `owner` role ==
// `<persona>:*`; every role grant is a valid pattern in the persona's own
// namespace; and parent edges reference declared personas and form an acyclic tree rooted
// at root.
func NewGroupSchema(types ...PersonaDef) (*GroupSchema, error) {
	s := &GroupSchema{types: make(map[string]PersonaDef, len(types))}
	for _, t := range types {
		if !segmentRe.MatchString(t.Name) {
			return nil, fmt.Errorf("group persona %q: name must match [a-z][a-z0-9-]*", t.Name)
		}
		if _, dup := s.types[t.Name]; dup {
			return nil, fmt.Errorf("group persona %q declared twice", t.Name)
		}
		eff, err := normalizePersona(t)
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

// normalizePersona validates a declared persona and injects the seeded owner
// role, returning the effective definition stored in the schema.
func normalizePersona(t PersonaDef) (PersonaDef, error) {
	catalog := map[string]struct{}{}
	if t.Capabilities.CustomRoles {
		for _, g := range t.Catalog {
			if err := ValidateGrantPattern(g); err != nil {
				return t, fmt.Errorf("group persona %q catalog: %w", t.Name, err)
			}
			if PermissionPersona(g) != t.Name {
				return t, fmt.Errorf("group persona %q catalog: grant %q is cross-persona", t.Name, g)
			}
			catalog[g] = struct{}{}
		}
	}

	byName := make(map[string]RoleDef, len(t.Roles)+1)
	order := make([]string, 0, len(t.Roles)+1)
	add := func(r RoleDef) {
		if _, ok := byName[r.Name]; !ok {
			order = append(order, r.Name)
		}
		byName[r.Name] = r
	}

	for _, r := range t.Roles {
		if r.Name == "" {
			return t, fmt.Errorf("group persona %q: a role has an empty name", t.Name)
		}
		if _, dup := byName[r.Name]; dup {
			return t, fmt.Errorf("group persona %q: role %q declared twice", t.Name, r.Name)
		}
		for _, g := range r.Permissions {
			if err := ValidateGrantPattern(g); err != nil {
				return t, fmt.Errorf("group persona %q role %q: %w", t.Name, r.Name, err)
			}
			if PermissionPersona(g) != t.Name {
				return t, fmt.Errorf("group persona %q role %q: grant %q is cross-persona — a %q role may hold only %q: perms", t.Name, r.Name, g, t.Name, t.Name)
			}
			if len(catalog) > 0 {
				if _, ok := catalog[g]; !ok {
					return t, fmt.Errorf("group persona %q role %q: grant %q is outside catalog", t.Name, r.Name, g)
				}
			}
		}
		add(r)
	}

	// Seed owner = <persona>:* (required; namespace-pure). If declared, it must match.
	want := OwnerGrant(t.Name)
	if owner, ok := byName[OwnerRoleName]; ok {
		if len(owner.Permissions) != 1 || owner.Permissions[0] != want {
			return t, fmt.Errorf("group persona %q: the %q role must hold exactly [%q]", t.Name, OwnerRoleName, want)
		}
	} else {
		add(RoleDef{Name: OwnerRoleName, Permissions: []string{want}})
	}

	eff := t
	eff.Roles = make([]RoleDef, 0, len(order))
	for _, n := range order {
		eff.Roles = append(eff.Roles, byName[n])
	}
	return eff, nil
}

// validateRoot enforces exactly one parentless persona, named RootPersona.
func (s *GroupSchema) validateRoot() (string, error) {
	var roots []string
	for name, t := range s.types {
		if strings.TrimSpace(t.Parent) == "" {
			roots = append(roots, name)
		}
	}
	switch len(roots) {
	case 0:
		return "", fmt.Errorf("no root persona declared (exactly one parentless persona, named %q, is required)", RootPersona)
	case 1:
		if roots[0] != RootPersona {
			return "", fmt.Errorf("the parentless persona must be named %q, got %q", RootPersona, roots[0])
		}
		return roots[0], nil
	default:
		sort.Strings(roots)
		return "", fmt.Errorf("exactly one root (parentless) persona is allowed; found %v", roots)
	}
}

// validateContainment checks every parent edge references a declared
// persona and that the child→parent graph is acyclic (so every persona reaches root).
func (s *GroupSchema) validateContainment() error {
	for name, t := range s.types {
		if name == RootPersona {
			continue
		}
		parent := strings.TrimSpace(t.Parent)
		if parent == "" {
			return fmt.Errorf("group persona %q: parent is required", name)
		}
		if parent == name {
			return fmt.Errorf("group persona %q: parent may not be itself", name)
		}
		if _, ok := s.types[parent]; !ok {
			return fmt.Errorf("group persona %q: parent %q is not a declared persona", name, parent)
		}
	}
	// Cycle detection over child → parent edges (root is the only sink).
	const (
		white = 0
		grey  = 1
		black = 2
	)
	color := make(map[string]int, len(s.types))
	var visit func(string, []string) error
	visit = func(n string, stack []string) error {
		color[n] = grey
		if p := strings.TrimSpace(s.types[n].Parent); p != "" {
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

// Persona returns a declared persona's effective definition.
func (s *GroupSchema) Persona(name string) (PersonaDef, bool) {
	t, ok := s.types[name]
	return t, ok
}

// RequireConsent reports whether admitting a new member to a group of this persona
// requires the invitee's acceptance (#193). Unknown personas default to false.
func (s *GroupSchema) RequireConsent(persona string) bool {
	t, ok := s.types[persona]
	return ok && t.RequireConsent
}

// Personas returns the declared persona names, sorted.
func (s *GroupSchema) Personas() []string {
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}

// IsRoot reports whether name is the root persona.
func (s *GroupSchema) IsRoot(name string) bool { return name == RootPersona }

// Roles returns a persona's effective roles (app-declared + seeded owner).
func (s *GroupSchema) Roles(persona string) ([]RoleDef, bool) {
	t, ok := s.types[persona]
	if !ok {
		return nil, false
	}
	out := make([]RoleDef, len(t.Roles))
	copy(out, t.Roles)
	return out, true
}

func (s *GroupSchema) GrantableUniverse(persona string) ([]string, bool) {
	t, ok := s.types[persona]
	if !ok {
		return nil, false
	}
	seen := map[string]struct{}{}
	add := func(g string) {
		if g != "" && g != OwnerGrant(persona) {
			seen[g] = struct{}{}
		}
	}
	if t.Capabilities.CustomRoles && len(t.Catalog) > 0 {
		for _, g := range t.Catalog {
			add(g)
		}
	} else {
		for _, r := range t.Roles {
			for _, g := range r.Permissions {
				add(g)
			}
		}
	}
	if persona == RootPersona {
		for _, g := range IntrinsicRootPermissions() {
			add(g)
		}
	}
	out := make([]string, 0, len(seen))
	for g := range seen {
		out = append(out, g)
	}
	sort.Strings(out)
	return out, true
}

// Role returns a single role from a persona's catalog.
func (s *GroupSchema) Role(persona, roleName string) (RoleDef, bool) {
	t, ok := s.types[persona]
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
// proposed (childPersona, parentPersona) edge. root is parentless; every non-root
// group needs the parent persona declared by the child persona's Parent — so
// e.g. `root -> repo` is structurally impossible, not merely discouraged.
func (s *GroupSchema) ValidateParent(childPersona, parentPersona string) error {
	ct, ok := s.types[childPersona]
	if !ok {
		return fmt.Errorf("unknown group persona %q", childPersona)
	}
	if childPersona == RootPersona {
		if parentPersona != "" {
			return fmt.Errorf("the root group is parentless; got parent persona %q", parentPersona)
		}
		return nil
	}
	if parentPersona == "" {
		return fmt.Errorf("a %q group requires parent persona %q", childPersona, ct.Parent)
	}
	if _, ok := s.types[parentPersona]; !ok {
		return fmt.Errorf("unknown parent group persona %q", parentPersona)
	}
	if ct.Parent == parentPersona {
		return nil
	}
	return fmt.Errorf("a %q group must have parent persona %q, got %q", childPersona, ct.Parent, parentPersona)
}
