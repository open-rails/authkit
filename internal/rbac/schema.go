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

// PersonaSpec is one declared persona, as the host configured it.
type PersonaSpec struct {
	Permissions        []string // app-defined catalog; AuthKit adds its built-ins
	RequireMFA         []string // permissions or patterns of the catalog that need MFA
	CustomRoles        bool
	APIKeys            bool
	RemoteApplications bool
}

// RoleSpec is one declared role, as the host configured it.
type RoleSpec struct {
	Persona     string
	Name        string
	Permissions []string
	Includes    []string // names of roles of the same persona
}

// Persona is a compiled persona.
type Persona struct {
	Name iam.Persona
	// Permissions is the complete catalog: app-declared plus built-ins, sorted.
	Permissions        []iam.Perm
	Roles              []Role // declared roles (includes flattened) plus owner
	CustomRoles        bool
	APIKeys            bool
	RemoteApplications bool
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

// New validates the host's personas and roles and compiles the schema. root
// always exists; a root entry in personas only adds app-specific root
// permissions and capabilities.
func New(personas map[string]PersonaSpec, roles []RoleSpec) (*Schema, error) {
	s := &Schema{
		personas: map[iam.Persona]Persona{},
		known:    map[iam.Perm]struct{}{},
	}
	specs := make(map[string]PersonaSpec, len(personas)+1)
	for name, spec := range personas {
		specs[name] = spec
	}
	root := iam.RootPersona.String()
	if _, ok := specs[root]; !ok {
		specs[root] = PersonaSpec{}
	}
	names := slices.Sorted(maps.Keys(specs))
	for _, raw := range names {
		if !iam.ValidPermissionSegment(raw) {
			return nil, fmt.Errorf("persona %q: name must match [a-z][a-z0-9-]*", raw)
		}
		name := ident.Persona(raw)
		p, err := s.compilePersona(name, specs[raw])
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
		Name:               name,
		CustomRoles:        spec.CustomRoles,
		APIKeys:            spec.APIKeys,
		RemoteApplications: spec.RemoteApplications,
	}
	catalog := map[iam.Perm]struct{}{}
	for _, raw := range spec.Permissions {
		raw = strings.TrimSpace(raw)
		if err := iam.ValidatePermission(raw); err != nil {
			return Persona{}, err
		}
		perm := ident.Perm(raw)
		if perm.Persona() != name {
			return Persona{}, fmt.Errorf("permission %q must start with %q", perm, name.String()+":")
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
	slices.SortFunc(p.Permissions, comparePerm)
	mfa := spec.RequireMFA
	if name == iam.RootPersona {
		// Handing out site-wide roles and editing other people's accounts
		// always need MFA, so the root owner does.
		mfa = append([]string{iam.PermMembersManage(name).String(), iam.PermRootUsersManage.String()}, mfa...)
	}
	for _, raw := range mfa {
		raw = strings.TrimSpace(raw)
		if err := iam.ValidateGrantPattern(raw); err != nil {
			return Persona{}, fmt.Errorf("RequireMFA: %w", err)
		}
		pattern := ident.Perm(raw)
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

// builtins returns the permissions AuthKit registers for a persona: members
// always, roles:manage with CustomRoles, credentials with APIKeys or
// RemoteApplications, and on root its intrinsic account permissions.
func builtins(name iam.Persona, spec PersonaSpec) []iam.Perm {
	out := []iam.Perm{iam.PermMembersRead(name), iam.PermMembersManage(name)}
	if spec.CustomRoles {
		out = append(out, iam.PermRolesManage(name))
	}
	if spec.APIKeys || spec.RemoteApplications {
		out = append(out, iam.PermCredentialsRead(name), iam.PermCredentialsManage(name))
	}
	if name == iam.RootPersona {
		out = append(out, iam.IntrinsicRootPermissions()...)
	}
	return out
}

func comparePerm(a, b iam.Perm) int { return cmp.Compare(a.String(), b.String()) }

func (s *Schema) compileRoles(specs []RoleSpec) error {
	declared := map[iam.Persona]map[string]RoleSpec{}
	order := map[iam.Persona][]string{}
	for _, r := range specs {
		r.Name = strings.TrimSpace(r.Name)
		persona := ident.Persona(strings.TrimSpace(r.Persona))
		if _, ok := s.personas[persona]; !ok {
			return fmt.Errorf("role %q: unknown persona %q", r.Name, r.Persona)
		}
		if !iam.ValidPermissionSegment(r.Name) {
			return fmt.Errorf("persona %q role %q: name must match [a-z][a-z0-9-]*", persona, r.Name)
		}
		if _, dup := declared[persona][r.Name]; dup {
			return fmt.Errorf("persona %q role %q declared twice", persona, r.Name)
		}
		for _, g := range r.Permissions {
			if err := s.validRoleGrant(persona, g); err != nil {
				return fmt.Errorf("persona %q role %q: %w", persona, r.Name, err)
			}
		}
		if declared[persona] == nil {
			declared[persona] = map[string]RoleSpec{}
		}
		declared[persona][r.Name] = r
		order[persona] = append(order[persona], r.Name)
	}

	for _, name := range s.order {
		roles := declared[name]
		if roles == nil {
			roles = map[string]RoleSpec{}
		}
		owner := name.OwnerGrant().String()
		ownerName := name.OwnerRole().Name()
		if o, ok := roles[ownerName]; ok {
			if len(o.Permissions) != 1 || o.Permissions[0] != owner || len(o.Includes) > 0 {
				return fmt.Errorf("persona %q: the %q role must hold exactly [%q]", name, ownerName, owner)
			}
		} else {
			roles[ownerName] = RoleSpec{Persona: name.String(), Name: ownerName, Permissions: []string{owner}}
			order[name] = append(order[name], ownerName)
		}
		p := s.personas[name]
		for _, role := range order[name] {
			grants, err := flatten(roles, role, nil)
			if err != nil {
				return fmt.Errorf("persona %q role %q: %w", name, role, err)
			}
			p.Roles = append(p.Roles, Role{Name: ident.Role(name, role), Permissions: grants, RequiresMFA: s.RequiresMFA(grants)})
		}
		s.personas[name] = p
	}
	return nil
}

// flatten returns role's grants unioned with every included role's, in
// declaration order. path holds the roles being expanded, to reject cycles.
func flatten(roles map[string]RoleSpec, role string, path []string) ([]string, error) {
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
		grants, err := flatten(roles, strings.TrimSpace(inc), path)
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
	pattern := ident.Perm(grant)
	target := pattern.Persona()
	if !mayHold(persona, target) {
		return fmt.Errorf("grant %q is cross-persona: a %q role may hold only %q permissions", grant, persona, persona.String()+":")
	}
	p, ok := s.personas[target]
	if !ok {
		return fmt.Errorf("grant %q names unknown persona %q", grant, target)
	}
	for _, perm := range p.Permissions {
		if perm.Matches(pattern) {
			return nil
		}
	}
	return fmt.Errorf("grant %q matches no permission in the %q catalog", grant, target)
}

// mayHold is the one rule for which persona's permissions a role may hold. A
// persona role holds only its own persona's. A root role may hold any
// persona's, since a role held on root applies in every group.
func mayHold(role, perm iam.Persona) bool { return role == iam.RootPersona || role == perm }

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

// MFAPermissions lists, sorted, the catalog permissions that need MFA.
func (s *Schema) MFAPermissions() []iam.Perm {
	return slices.SortedFunc(slices.Values(s.mfa), comparePerm)
}

// CustomRoleGrantsValid checks the grants of a runtime-defined role: each must
// match the persona's catalog, and none may be the owner grant.
func (s *Schema) CustomRoleGrantsValid(persona iam.Persona, grants []string) error {
	for _, g := range grants {
		if err := iam.ValidateGrantPattern(g); err != nil {
			return fmt.Errorf("%w: %w", iam.ErrCustomRoleGrantOutsideCatalog, err)
		}
		if ident.Perm(g).Persona() != persona {
			return fmt.Errorf("custom role grant %q is cross-persona: %w", g, iam.ErrCustomRoleGrantCrossPersona)
		}
		if ident.Perm(g) == persona.OwnerGrant() {
			return fmt.Errorf("custom role grant %q is the owner grant: %w", g, iam.ErrCustomRoleGrantOutsideCatalog)
		}
		if err := s.validRoleGrant(persona, g); err != nil {
			return fmt.Errorf("custom role grant %q is outside catalog: %w", g, iam.ErrCustomRoleGrantOutsideCatalog)
		}
	}
	return nil
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

// ParseRole resolves a role name read at run time for groups of persona: a
// catalog role or, when the persona has CustomRoles, any valid custom-role
// name, whose definition in the group is checked where the role is used.
func (s *Schema) ParseRole(persona iam.Persona, name string) (iam.Role, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	p, ok := s.personas[persona]
	if !ok || persona.IsZero() {
		return iam.Role{}, fmt.Errorf("unknown persona %q: %w", persona, iam.ErrUnknownGroupPersona)
	}
	if r, ok := s.RoleNamed(persona, name); ok {
		return r.Name, nil
	}
	if p.CustomRoles && iam.ValidPermissionSegment(name) {
		return ident.Role(persona, name), nil
	}
	return iam.Role{}, fmt.Errorf("%q is not a role of %q: %w", name, persona, iam.ErrRoleNotAssignable)
}

// RoleNamed returns persona's catalog role name.
func (s *Schema) RoleNamed(persona iam.Persona, name string) (Role, bool) {
	return s.Role(persona, ident.Role(persona, strings.TrimSpace(name)))
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

// ResolveGrants returns the de-duplicated union of grant patterns a subject
// holds in the group with id target, across its assignments on that group and
// on root. Root is the widest scope: a root role's persona permissions apply in
// every group, but root's own `root:` permissions count only in root itself.
// Unknown personas and roles contribute nothing (fail closed).
func (s *Schema) ResolveGrants(target string, assignments []Assignment, custom CustomRoleResolver) []string {
	seen := map[string]bool{}
	var out []string
	add := func(a Assignment, grants []string) {
		for _, g := range grants {
			if g == "" || seen[g] || a.PermissionGroupID != target && ident.Perm(g).Persona() == iam.RootPersona {
				continue
			}
			seen[g] = true
			out = append(out, g)
		}
	}
	for _, a := range assignments {
		p, ok := s.personas[a.Persona]
		if !ok || a.Role.IsZero() {
			continue
		}
		if r, ok := s.Role(a.Persona, a.Role); ok {
			add(a, r.Permissions)
			continue
		}
		if p.CustomRoles && custom != nil {
			if grants, ok := custom(a.PermissionGroupID, a.Role); ok {
				add(a, grants)
			}
		}
	}
	return out
}
