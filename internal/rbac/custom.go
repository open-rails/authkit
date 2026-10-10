package rbac

import (
	"fmt"
	"slices"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
)

// A custom role is one a group defines at run time, held only in that group:
// `<persona>:custom-<name>`. Declared role names never start with
// CustomPrefix, so the two never meet, whatever a later deploy declares.
const (
	CustomPrefix = "custom-"
	// MaxCustomName bounds the name a group gives a custom role.
	MaxCustomName = 64
	// MaxCustomGrants bounds what one custom role holds.
	MaxCustomGrants = 256
)

// IsCustom reports whether role is a custom role's name.
func IsCustom(role iam.Role) bool { return strings.HasPrefix(role.Name(), CustomPrefix) }

// CustomRole is persona's custom role named name (`storefront` is
// `<persona>:custom-storefront`); ok is false for an invalid name.
func CustomRole(persona iam.Persona, name string) (iam.Role, bool) {
	if len(name) > MaxCustomName || !ident.ValidSegment(name) {
		return iam.Role{}, false
	}
	r := ident.Role(persona, CustomPrefix+name)
	return r, !r.IsZero()
}

// CustomName is the name a group gave the custom role.
func CustomName(role iam.Role) string { return strings.TrimPrefix(role.Name(), CustomPrefix) }

// CustomGrants validates what a custom role of persona would hold and returns
// it de-duplicated, in order: permissions or namespace-anchored patterns that
// a declared role of the persona may hold (a persona role its own persona's,
// a root role any persona's), each matching a catalog permission. A custom
// role includes no other role.
func (s *Schema) CustomGrants(persona iam.Persona, grants []iam.Perm) ([]string, error) {
	p, ok := s.personas[persona]
	if !ok || !p.CustomRoles {
		return nil, fmt.Errorf("persona %q defines no custom roles", persona)
	}
	out := make([]string, 0, len(grants))
	for _, g := range grants {
		text := g.String()
		if err := ident.ValidateGrantPattern(text); err != nil {
			return nil, err
		}
		if err := s.validRoleGrant(persona, g); err != nil {
			return nil, err
		}
		if !slices.Contains(out, text) {
			out = append(out, text)
		}
	}
	if len(out) == 0 || len(out) > MaxCustomGrants {
		return nil, fmt.Errorf("a custom role holds 1 to %d permissions", MaxCustomGrants)
	}
	return out, nil
}

// AssignedRole is the role a subject holds in a group of persona: a declared
// role, or a custom role with stored, what the group stores for it (nil: the
// group defines none). A custom role confers only the grants a declared role
// of the persona could hold, and nothing once the persona stops defining
// custom roles.
func (s *Schema) AssignedRole(persona iam.Persona, role iam.Role, stored []string) (Role, bool) {
	if role.IsZero() || role.Persona() != persona {
		return Role{}, false
	}
	if !IsCustom(role) {
		return s.Role(persona, role)
	}
	if p, ok := s.personas[persona]; !ok || !p.CustomRoles || stored == nil {
		return Role{}, false
	}
	grants := make([]string, 0, len(stored))
	for _, g := range stored {
		if ident.ValidateGrantPattern(g) == nil && mayHold(persona, ident.Perm(g).Persona()) && !slices.Contains(grants, g) {
			grants = append(grants, g)
		}
	}
	return Role{Name: role, Permissions: grants, RequiresMFA: s.RequiresMFA(grants)}, true
}
