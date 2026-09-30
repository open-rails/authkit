// Package rbac compiles the host's role configuration into the immutable
// schema the engine authorizes against: each persona's permission catalog, its
// roles, and the pure grant-resolution core. It depends only on the standard
// library and iam, and has no database.
//
// A persona is a type of permission group (channel, org, merchant). A
// permission group is one instance of a persona. root is the persona with
// exactly one group, the whole site.
package rbac

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
)

// PersonaSpec is one declared persona, built by the Roles builder: its names
// are valid by construction.
type PersonaSpec struct {
	Name               iam.Persona
	Permissions        []iam.Perm // app-defined catalog; AuthKit adds its built-ins
	RequireMFA         []iam.Perm // permissions or patterns of the catalog that need MFA
	APIKeys            bool
	RemoteApplications bool
}

// RoleSpec is one declared role.
type RoleSpec struct {
	Name     iam.Role
	Grants   []iam.Perm // permissions or patterns
	Includes []iam.Role // roles of the same persona
}

// Persona is a compiled persona.
type Persona struct {
	Name iam.Persona
	// Permissions is the complete catalog: app-declared plus built-ins, sorted.
	Permissions []iam.Perm
	Roles       []Role // declared roles (includes flattened) plus owner
	APIKeys     bool
}

// Role is a compiled role: its grant patterns with includes flattened.
// RequiresMFA is derived: the grants reach an MFA permission.
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
	mfa      []iam.Perm // concrete permissions that need MFA, every persona
}

// Default is the root-only schema.
func Default() *Schema {
	s, err := New(nil, nil)
	if err != nil {
		panic(err)
	}
	return s
}

// New compiles the declared personas and roles, checking what the builder
// cannot see while declaring: catalogs, grants, includes and MFA patterns.
// root always exists; a root entry only adds app permissions and
// capabilities.
func New(personas []PersonaSpec, roles []RoleSpec) (*Schema, error) {
	s := &Schema{
		personas: map[iam.Persona]Persona{},
		known:    map[iam.Perm]struct{}{},
	}
	specs := map[iam.Persona]PersonaSpec{iam.RootPersona(): {Name: iam.RootPersona()}}
	for _, spec := range personas {
		specs[spec.Name] = spec
	}
	names := slices.SortedFunc(maps.Keys(specs), func(a, b iam.Persona) int { return cmp.Compare(a.String(), b.String()) })
	for _, name := range names {
		p, err := s.compilePersona(name, specs[name])
		if err != nil {
			return nil, fmt.Errorf("persona %q: %w", name, err)
		}
		s.personas[name] = p
		s.order = append(s.order, name)
	}
	if err := s.compileRoles(roles); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Schema) compilePersona(name iam.Persona, spec PersonaSpec) (Persona, error) {
	p := Persona{
		Name:    name,
		APIKeys: spec.APIKeys,
	}
	for _, perm := range spec.Permissions {
		if perm.Persona() != name {
			return Persona{}, fmt.Errorf("permission %q must start with %q", perm, name.String()+":")
		}
	}
	p.Permissions = Catalog(spec)
	for _, perm := range p.Permissions {
		s.known[perm] = struct{}{}
	}
	mfa := spec.RequireMFA
	if name == iam.RootPersona() {
		// Handing out site-wide roles and editing other people's accounts
		// always need MFA, so the root owner does.
		mfa = append([]iam.Perm{ident.MembersManage(name), ident.RootUsersManage}, mfa...)
	}
	for _, pattern := range mfa {
		if pattern.Persona() != name {
			return Persona{}, fmt.Errorf("RequireMFA %q must start with %q", pattern, name.String()+":")
		}
		matched := false
		for _, perm := range p.Permissions {
			if perm.Matches(pattern) {
				matched = true
				if !slices.Contains(s.mfa, perm) {
					s.mfa = append(s.mfa, perm)
				}
			}
		}
		if !matched {
			return Persona{}, fmt.Errorf("RequireMFA %q matches no permission in the catalog", pattern)
		}
	}
	return p, nil
}

// Catalog is a persona's complete catalog: its declared permissions and the
// built-ins AuthKit registers, sorted.
func Catalog(spec PersonaSpec) []iam.Perm {
	set := map[iam.Perm]struct{}{}
	for _, perm := range spec.Permissions {
		set[perm] = struct{}{}
	}
	for _, perm := range Builtins(spec.Name, spec.APIKeys || spec.RemoteApplications) {
		set[perm] = struct{}{}
	}
	return slices.SortedFunc(maps.Keys(set), comparePerm)
}

// Expand lists every permission of catalog some grant pattern covers, in
// catalog order: what a client checks by set membership.
func Expand(catalog, grants []iam.Perm) []iam.Perm {
	out := []iam.Perm{}
	for _, p := range catalog {
		if slices.ContainsFunc(grants, p.Matches) {
			out = append(out, p)
		}
	}
	return out
}

// Builtins returns the permissions AuthKit registers for a persona: members
// always, credentials when it has API keys or remote applications, and on
// root its intrinsic account permissions.
func Builtins(name iam.Persona, credentials bool) []iam.Perm {
	out := []iam.Perm{ident.MembersRead(name), ident.MembersManage(name)}
	if credentials {
		out = append(out, ident.CredentialsRead(name), ident.CredentialsManage(name))
	}
	if name == iam.RootPersona() {
		out = append(out, ident.IntrinsicRootPermissions()...)
	}
	return out
}

func comparePerm(a, b iam.Perm) int { return cmp.Compare(a.String(), b.String()) }

func (s *Schema) compileRoles(specs []RoleSpec) error {
	declared := map[iam.Persona]map[iam.Role]RoleSpec{}
	order := map[iam.Persona][]iam.Role{}
	for _, r := range specs {
		persona := r.Name.Persona()
		if _, ok := s.personas[persona]; !ok {
			return fmt.Errorf("role %q: unknown persona %q", r.Name, persona)
		}
		if _, dup := declared[persona][r.Name]; dup {
			return fmt.Errorf("role %q declared twice", r.Name)
		}
		for _, g := range r.Grants {
			if err := s.validRoleGrant(persona, g); err != nil {
				return fmt.Errorf("role %q: %w", r.Name, err)
			}
		}
		if declared[persona] == nil {
			declared[persona] = map[iam.Role]RoleSpec{}
		}
		declared[persona][r.Name] = r
		order[persona] = append(order[persona], r.Name)
	}

	for _, name := range s.order {
		roles := declared[name]
		if roles == nil {
			roles = map[iam.Role]RoleSpec{}
		}
		owner := name.OwnerRole()
		if _, ok := roles[owner]; ok {
			return fmt.Errorf("persona %q: the %q role is built in", name, owner.Name())
		}
		roles[owner] = RoleSpec{Name: owner, Grants: s.ownerGrants(name)}
		order[name] = append(order[name], owner)
		p := s.personas[name]
		for _, role := range order[name] {
			grants, err := flatten(roles, role, nil)
			if err != nil {
				return fmt.Errorf("role %q: %w", role, err)
			}
			p.Roles = append(p.Roles, Role{Name: role, Permissions: grants, RequiresMFA: s.RequiresMFA(grants)})
		}
		s.personas[name] = p
	}
	return nil
}

// ownerGrants is what persona's owner holds: `<persona>:*`. The root owner
// also holds every other persona's, so the site owner acts in every group.
func (s *Schema) ownerGrants(persona iam.Persona) []iam.Perm {
	out := []iam.Perm{persona.OwnerGrant()}
	if persona == iam.RootPersona() {
		for _, p := range s.order {
			if p != iam.RootPersona() {
				out = append(out, p.OwnerGrant())
			}
		}
	}
	return out
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
	out := ident.Strings(r.Grants)
	for _, inc := range r.Includes {
		grants, err := flatten(roles, inc, path)
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
func (s *Schema) validRoleGrant(persona iam.Persona, pattern iam.Perm) error {
	target := pattern.Persona()
	if !mayHold(persona, target) {
		return fmt.Errorf("grant %q is cross-persona: a %q role may hold only %q permissions", pattern, persona, persona.String()+":")
	}
	p, ok := s.personas[target]
	if !ok {
		return fmt.Errorf("grant %q names unknown persona %q", pattern, target)
	}
	for _, perm := range p.Permissions {
		if perm.Matches(pattern) {
			return nil
		}
	}
	return fmt.Errorf("grant %q matches no permission in the %q catalog", pattern, target)
}

// mayHold is the one rule for which persona's permissions a role may hold. A
// persona role holds only its own persona's. A root role may hold any
// persona's, since a role held on root applies in every group.
func mayHold(role, perm iam.Persona) bool { return role == iam.RootPersona() || role == perm }

// RequiresMFA reports whether grants reach a permission that needs MFA. MFA
// follows permissions, not role names: a clone, an include or a root role
// holding such a permission needs MFA as much as the role that first held it.
func (s *Schema) RequiresMFA(grants []string) bool {
	for _, perm := range s.mfa {
		if Covers(grants, perm) {
			return true
		}
	}
	return false
}

// Covers reports whether any grant pattern covers the concrete perm.
func Covers(grants []string, perm iam.Perm) bool {
	for _, g := range grants {
		if perm.Matches(ident.Perm(g)) {
			return true
		}
	}
	return false
}

// CoversAll reports whether grants cover every grant in perms, patterns
// included.
func CoversAll(grants, perms []string) bool {
	for _, p := range perms {
		if !Covers(grants, ident.Perm(p)) {
			return false
		}
	}
	return true
}

// MFAPermissions lists, sorted, the catalog permissions that need MFA.
func (s *Schema) MFAPermissions() []iam.Perm {
	return slices.SortedFunc(slices.Values(s.mfa), comparePerm)
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

// PersonaNamed resolves a persona name read at run time.
func (s *Schema) PersonaNamed(name string) (iam.Persona, bool) {
	p := ident.Persona(strings.TrimSpace(name))
	_, ok := s.personas[p]
	return p, ok && !p.IsZero()
}

// Permission resolves a registered concrete permission read at run time.
func (s *Schema) Permission(text string) (iam.Perm, bool) {
	p := ident.Perm(strings.TrimSpace(text))
	return p, !p.IsZero() && s.KnownPermission(p)
}

// Roles returns a persona's roles.
func (s *Schema) Roles(persona iam.Persona) ([]Role, bool) {
	p, ok := s.personas[persona]
	return slices.Clone(p.Roles), ok
}

// Role returns a catalog role of persona; a role of another persona is not one.
func (s *Schema) Role(persona iam.Persona, role iam.Role) (Role, bool) {
	if role.Persona() != persona {
		return Role{}, false
	}
	for _, r := range s.personas[persona].Roles {
		if r.Name == role {
			return r, true
		}
	}
	return Role{}, false
}

// RoleNamed returns persona's catalog role name.
func (s *Schema) RoleNamed(persona iam.Persona, name string) (Role, bool) {
	return s.Role(persona, ident.Role(persona, strings.TrimSpace(name)))
}

// Assignment is a subject's single role in one permission group, tagged with
// that group's persona.
type Assignment struct {
	Persona           iam.Persona
	PermissionGroupID string
	Role              iam.Role
}

// ResolveGrants returns the de-duplicated union of grant patterns a subject
// holds in the group with id target, across its assignments on that group and
// on root. Root is the widest scope: a root role's persona permissions apply in
// every group, but root's own `root:` permissions count only in root itself.
// Unknown personas and roles contribute nothing (fail closed).
func (s *Schema) ResolveGrants(target string, assignments []Assignment) []string {
	seen := map[string]bool{}
	var out []string
	add := func(a Assignment, grants []string) {
		for _, g := range grants {
			if g == "" || seen[g] || a.PermissionGroupID != target && ident.Perm(g).Persona() == iam.RootPersona() {
				continue
			}
			seen[g] = true
			out = append(out, g)
		}
	}
	for _, a := range assignments {
		if r, ok := s.Role(a.Persona, a.Role); ok && !a.Role.IsZero() {
			add(a, r.Permissions)
		}
	}
	return out
}
