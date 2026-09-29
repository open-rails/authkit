// Package rbac compiles the host's role configuration into the immutable
// schema the engine authorizes against: each persona's permission catalog, its
// roles, and the pure grant-resolution core. It depends only on the standard
// library and iam, and has no database.
//
// A persona is a type of permission group (channel, org, merchant). A
// permission group is one instance of a persona (/c/golang). root is the
// persona with exactly one group, the whole site.
package rbac

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/open-rails/authkit/iam"
)

// PersonaSpec is one declared persona, as the host configured it.
type PersonaSpec struct {
	Permissions        []string // app-defined catalog; AuthKit adds its built-ins
	Creation           Creation
	CustomRoles        bool
	APIKeys            bool
	RemoteApplications bool
}

// RoleSpec is one declared role, as the host configured it.
type RoleSpec struct {
	Persona     iam.Persona
	Name        iam.Role
	Permissions []string
	Includes    []iam.Role
	RequiresMFA bool
}

// Creation configures the generated POST /<persona> route. ReservedSlugs are
// creatable only by actors holding `<persona>:*` on root.
type Creation struct {
	Enabled       bool
	SlugPattern   string
	ReservedSlugs []string
}

// Persona is a compiled persona.
type Persona struct {
	Name iam.Persona
	// Permissions is the complete catalog: app-declared plus built-ins, sorted.
	Permissions        []iam.Perm
	Roles              []Role // declared roles (includes flattened) plus owner
	Creation           Creation
	CustomRoles        bool
	APIKeys            bool
	RemoteApplications bool
}

// Role is a compiled role: its grant patterns with includes flattened.
type Role struct {
	Name        iam.Role
	Permissions []string
	RequiresMFA bool
}

// Schema is the validated, immutable role configuration.
type Schema struct {
	personas map[iam.Persona]Persona
	order    []iam.Persona
	known    map[iam.Perm]struct{}
	patterns map[iam.Persona]*regexp.Regexp
}

// Default is the root-only schema.
func Default() *Schema {
	s, err := New(nil, nil)
	if err != nil {
		panic(err)
	}
	return s
}

// New validates the host's personas and roles and compiles the schema. root
// always exists; a root entry in personas only adds app-specific root
// permissions and capabilities.
func New(personas map[iam.Persona]PersonaSpec, roles []RoleSpec) (*Schema, error) {
	s := &Schema{
		personas: map[iam.Persona]Persona{},
		known:    map[iam.Perm]struct{}{},
		patterns: map[iam.Persona]*regexp.Regexp{},
	}
	specs := make(map[iam.Persona]PersonaSpec, len(personas)+1)
	for name, spec := range personas {
		specs[name] = spec
	}
	if _, ok := specs[iam.RootPersona]; !ok {
		specs[iam.RootPersona] = PersonaSpec{}
	}
	for name := range specs {
		s.order = append(s.order, name)
	}
	slices.Sort(s.order)
	for _, name := range s.order {
		p, err := s.compilePersona(name, specs[name])
		if err != nil {
			return nil, fmt.Errorf("persona %q: %w", name, err)
		}
		s.personas[name] = p
	}
	if err := s.compileRoles(roles); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Schema) compilePersona(name iam.Persona, spec PersonaSpec) (Persona, error) {
	if !iam.ValidPermissionSegment(string(name)) {
		return Persona{}, errors.New("name must match [a-z][a-z0-9-]*")
	}
	p := Persona{
		Name:               name,
		CustomRoles:        spec.CustomRoles,
		APIKeys:            spec.APIKeys,
		RemoteApplications: spec.RemoteApplications,
	}
	catalog := map[iam.Perm]struct{}{}
	for _, raw := range spec.Permissions {
		perm := iam.Perm(strings.TrimSpace(raw))
		if err := iam.ValidatePermission(string(perm)); err != nil {
			return Persona{}, err
		}
		if perm.Persona() != name {
			return Persona{}, fmt.Errorf("permission %q must start with %q", perm, name+":")
		}
		if resource(perm) == iam.SelfResource {
			return Persona{}, fmt.Errorf("permission %q: the %q resource is reserved to AuthKit", perm, iam.SelfResource)
		}
		catalog[perm] = struct{}{}
	}
	for _, perm := range builtins(name, spec) {
		catalog[perm] = struct{}{}
	}
	for perm := range catalog {
		p.Permissions = append(p.Permissions, perm)
		s.known[perm] = struct{}{}
	}
	slices.Sort(p.Permissions)

	c := spec.Creation
	if c.Enabled && name == iam.RootPersona {
		return Persona{}, errors.New("the root group is a singleton; creation cannot be enabled")
	}
	p.Creation = Creation{Enabled: c.Enabled, SlugPattern: strings.TrimSpace(c.SlugPattern)}
	if p.Creation.SlugPattern != "" {
		re, err := regexp.Compile("^(?:" + p.Creation.SlugPattern + ")$")
		if err != nil {
			return Persona{}, fmt.Errorf("creation slug pattern: %w", err)
		}
		s.patterns[name] = re
	}
	for _, raw := range c.ReservedSlugs {
		slug := strings.ToLower(strings.TrimSpace(raw))
		if !iam.ValidSlug(slug) {
			return Persona{}, fmt.Errorf("reserved slug %q must be lowercase URL-safe", raw)
		}
		p.Creation.ReservedSlugs = append(p.Creation.ReservedSlugs, slug)
	}
	return p, nil
}

// builtins returns the permissions AuthKit registers for a persona: members
// always, roles:manage with CustomRoles, credentials with APIKeys or
// RemoteApplications, and self except on root, which adds its intrinsic
// permissions instead (its group cannot be read, renamed or deleted as a group).
func builtins(name iam.Persona, spec PersonaSpec) []iam.Perm {
	out := []iam.Perm{iam.PermMembersRead(name), iam.PermMembersManage(name)}
	if spec.CustomRoles {
		out = append(out, iam.PermRolesManage(name))
	}
	if spec.APIKeys || spec.RemoteApplications {
		out = append(out, iam.PermCredentialsRead(name), iam.PermCredentialsManage(name))
	}
	if name == iam.RootPersona {
		for _, perm := range iam.IntrinsicRootPermissions() {
			out = append(out, iam.Perm(perm))
		}
		return out
	}
	return append(out, iam.PermSelfRead(name), iam.PermSelfUpdate(name), iam.PermSelfDelete(name))
}

func (s *Schema) compileRoles(specs []RoleSpec) error {
	declared := map[iam.Persona]map[iam.Role]RoleSpec{}
	order := map[iam.Persona][]iam.Role{}
	for _, r := range specs {
		r.Persona = iam.Persona(strings.TrimSpace(string(r.Persona)))
		r.Name = iam.Role(strings.TrimSpace(string(r.Name)))
		if _, ok := s.personas[r.Persona]; !ok {
			return fmt.Errorf("role %q: unknown persona %q", r.Name, r.Persona)
		}
		if !iam.ValidPermissionSegment(string(r.Name)) {
			return fmt.Errorf("persona %q role %q: name must match [a-z][a-z0-9-]*", r.Persona, r.Name)
		}
		if _, dup := declared[r.Persona][r.Name]; dup {
			return fmt.Errorf("persona %q role %q declared twice", r.Persona, r.Name)
		}
		for _, g := range r.Permissions {
			if err := s.validRoleGrant(r.Persona, g); err != nil {
				return fmt.Errorf("persona %q role %q: %w", r.Persona, r.Name, err)
			}
		}
		if declared[r.Persona] == nil {
			declared[r.Persona] = map[iam.Role]RoleSpec{}
		}
		declared[r.Persona][r.Name] = r
		order[r.Persona] = append(order[r.Persona], r.Name)
	}

	for _, name := range s.order {
		roles := declared[name]
		if roles == nil {
			roles = map[iam.Role]RoleSpec{}
		}
		owner := string(name.OwnerGrant())
		if o, ok := roles[iam.OwnerRole]; ok {
			if len(o.Permissions) != 1 || o.Permissions[0] != owner || len(o.Includes) > 0 {
				return fmt.Errorf("persona %q: the %q role must hold exactly [%q]", name, iam.OwnerRole, owner)
			}
		} else {
			// The apex root:* role must never be the one role that forgot 2FA.
			roles[iam.OwnerRole] = RoleSpec{Persona: name, Name: iam.OwnerRole, Permissions: []string{owner}, RequiresMFA: name == iam.RootPersona}
			order[name] = append(order[name], iam.OwnerRole)
		}
		p := s.personas[name]
		for _, role := range order[name] {
			grants, err := flatten(roles, role, nil)
			if err != nil {
				return fmt.Errorf("persona %q role %q: %w", name, role, err)
			}
			p.Roles = append(p.Roles, Role{Name: role, Permissions: grants, RequiresMFA: roles[role].RequiresMFA})
		}
		s.personas[name] = p
	}
	return nil
}

// flatten returns role's grants unioned with every included role's, in
// declaration order. path holds the roles being expanded, to reject cycles.
func flatten(roles map[iam.Role]RoleSpec, role iam.Role, path []iam.Role) ([]string, error) {
	if slices.Contains(path, role) {
		return nil, fmt.Errorf("includes cycle %v", append(path, role))
	}
	r, ok := roles[role]
	if !ok {
		return nil, fmt.Errorf("includes unknown role %q", role)
	}
	path = append(path, role)
	out := append([]string(nil), r.Permissions...)
	for _, inc := range r.Includes {
		grants, err := flatten(roles, iam.Role(strings.TrimSpace(string(inc))), path)
		if err != nil {
			return nil, err
		}
		for _, g := range grants {
			if !slices.Contains(out, g) {
				out = append(out, g)
			}
		}
	}
	return out, nil
}

// validRoleGrant checks one grant of a role held in groups of persona: the
// role may hold the grant's persona, and the grant names at least one
// registered permission.
func (s *Schema) validRoleGrant(persona iam.Persona, grant string) error {
	if err := iam.ValidateGrantPattern(grant); err != nil {
		return err
	}
	target := iam.Perm(grant).Persona()
	if !mayHold(persona, target) {
		return fmt.Errorf("grant %q is cross-persona: a %q role may hold only %q permissions", grant, persona, string(persona)+":")
	}
	p, ok := s.personas[target]
	if !ok {
		return fmt.Errorf("grant %q names unknown persona %q", grant, target)
	}
	for _, perm := range p.Permissions {
		if perm.Matches(iam.Perm(grant)) {
			return nil
		}
	}
	return fmt.Errorf("grant %q matches no permission in the %q catalog", grant, target)
}

// mayHold is the one rule for which persona's permissions a role may hold. A
// persona role holds only its own persona's. A root role may hold any
// persona's, since a role held on root applies in every group.
func mayHold(role, perm iam.Persona) bool { return role == iam.RootPersona || role == perm }

// CustomRoleGrantsValid checks the grants of a runtime-defined role: each must
// match the persona's catalog, and none may be the owner grant.
func (s *Schema) CustomRoleGrantsValid(persona iam.Persona, grants []string) error {
	for _, g := range grants {
		if err := iam.ValidateGrantPattern(g); err != nil {
			return fmt.Errorf("%w: %w", iam.ErrCustomRoleGrantOutsideCatalog, err)
		}
		if iam.Perm(g).Persona() != persona {
			return fmt.Errorf("custom role grant %q is cross-persona: %w", g, iam.ErrCustomRoleGrantCrossPersona)
		}
		if iam.Perm(g) == persona.OwnerGrant() {
			return fmt.Errorf("custom role grant %q is the owner grant: %w", g, iam.ErrCustomRoleGrantOutsideCatalog)
		}
		if err := s.validRoleGrant(persona, g); err != nil {
			return fmt.Errorf("custom role grant %q is outside catalog: %w", g, iam.ErrCustomRoleGrantOutsideCatalog)
		}
	}
	return nil
}

func resource(p iam.Perm) string {
	segs := strings.Split(string(p), ":")
	if len(segs) < 2 {
		return ""
	}
	return segs[1]
}

// KnownPermission reports whether perm is a concrete permission registered in
// some persona's catalog.
func (s *Schema) KnownPermission(perm iam.Perm) bool {
	_, ok := s.known[perm]
	return ok
}

// Persona returns a persona's compiled definition.
func (s *Schema) Persona(name iam.Persona) (Persona, bool) {
	p, ok := s.personas[name]
	return p, ok
}

// Personas returns the persona names, sorted; root is always present.
func (s *Schema) Personas() []iam.Persona { return slices.Clone(s.order) }

// Roles returns a persona's roles.
func (s *Schema) Roles(persona iam.Persona) ([]Role, bool) {
	p, ok := s.personas[persona]
	return slices.Clone(p.Roles), ok
}

// Role returns one role of a persona.
func (s *Schema) Role(persona iam.Persona, role iam.Role) (Role, bool) {
	for _, r := range s.personas[persona].Roles {
		if r.Name == role {
			return r, true
		}
	}
	return Role{}, false
}

// CreationEnabled reports whether the persona has the generated creation route.
func (s *Schema) CreationEnabled(persona iam.Persona) bool {
	return s.personas[persona].Creation.Enabled
}

// CreationSlugAllowed applies the persona's SlugPattern; the built-in slug
// rule is enforced separately.
func (s *Schema) CreationSlugAllowed(persona iam.Persona, slug string) bool {
	re, ok := s.patterns[persona]
	return !ok || re.MatchString(slug)
}

// SlugReserved reports whether slug is one of the persona's reserved slugs.
func (s *Schema) SlugReserved(persona iam.Persona, slug string) bool {
	return slices.Contains(s.personas[persona].Creation.ReservedSlugs, strings.ToLower(strings.TrimSpace(slug)))
}

// Assignment is a subject's single role in one permission group, tagged with
// that group's persona.
type Assignment struct {
	Persona           iam.Persona
	PermissionGroupID string // scopes custom-role lookups
	Role              iam.Role
}

// CustomRoleResolver returns a group's custom role grants, or false if the
// group defines no such role.
type CustomRoleResolver func(groupID string, role iam.Role) ([]string, bool)

// ResolveGrants returns the de-duplicated union of grant patterns across
// assignments. Unknown personas and roles contribute nothing (fail closed).
func (s *Schema) ResolveGrants(assignments []Assignment, custom CustomRoleResolver) []string {
	seen := map[string]bool{}
	var out []string
	add := func(grants []string) {
		for _, g := range grants {
			if g != "" && !seen[g] {
				seen[g] = true
				out = append(out, g)
			}
		}
	}
	for _, a := range assignments {
		p, ok := s.personas[a.Persona]
		if !ok || a.Role == "" {
			continue
		}
		if r, ok := s.Role(a.Persona, a.Role); ok {
			add(r.Permissions)
			continue
		}
		if p.CustomRoles && custom != nil {
			if grants, ok := custom(a.PermissionGroupID, a.Role); ok {
				add(grants)
			}
		}
	}
	return out
}

// Can reports whether any grant resolved from assignments covers perm.
func (s *Schema) Can(assignments []Assignment, custom CustomRoleResolver, perm iam.Perm) bool {
	return iam.AnyGrantCovers(s.ResolveGrants(assignments, custom), perm)
}
