package authcore

// Authorization decision core for the permission-group model (#111): the
// additive walk-up UNION + namespace-anchored coverage. These are PURE functions
// over an already-resolved assignment set — the engine (later milestone) loads a
// target group's parent chain + the subject's assignments from the database and
// feeds them here. Keeping the decision pure makes it exhaustively unit-testable
// without a database and keeps the authz-critical matching in one place.

import "github.com/open-rails/authkit/authbase"

// GroupAssignment is a subject's role-assignment set within ONE permission-group,
// tagged with that group's persona. The engine produces a slice of these by walking
// a target group's parent chain (resolving the subject's roles at each level);
// the slice order is irrelevant — the union is additive and order-independent.
type GroupAssignment struct {
	Persona           string   // the declared persona of the group this assignment lives in
	PermissionGroupID string   // opaque group id; used ONLY to scope custom-role lookups
	Roles             []string // role names the subject holds in this group
}

// CustomRoleResolver returns the grant tokens of a per-group custom role, or
// (nil, false) if no such custom role exists. Consulted only for personas whose
// AllowCustomRoles is set; pass nil when the deployment defines no custom roles.
type CustomRoleResolver func(groupID, role string) ([]string, bool)

// ResolveGrants computes the additive, de-duplicated UNION of grant tokens a
// subject holds across the given assignments. For each (persona, role): a
// catalog role contributes the persona's catalog grants; otherwise, if the persona
// allows custom roles, the per-group custom role's grants are used. Unknown
// personas and unknown roles contribute NOTHING (fail-closed). Every returned token
// is a grant pattern already validated at schema-construction time.
func (s *GroupSchema) ResolveGrants(assignments []GroupAssignment, custom CustomRoleResolver) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(g string) {
		if g != "" && !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	for _, a := range assignments {
		td, ok := s.types[a.Persona]
		if !ok {
			continue // unknown persona: fail-closed
		}
		for _, role := range a.Roles {
			if r, ok := roleByName(td.Roles, role); ok {
				for _, g := range r.Permissions {
					add(g)
				}
				continue
			}
			if td.AllowCustomRoles && custom != nil {
				if grants, ok := custom(a.PermissionGroupID, role); ok {
					for _, g := range grants {
						add(g)
					}
				}
			}
		}
	}
	return out
}

// Can reports whether the subject (via its assignments across a target group's
// parent chain) holds a grant covering perm. ALLOW if any granted token covers
// perm under authkit's namespace-anchored glob semantics (a bare `*` never
// matches). Additive walk-up union; the caller constructs the exact perm to
// check (e.g. for a resource of persona RT acted on from an ancestor of persona LT,
// the perm is `LT:RT:<action>` — the two-persona rule, decision #5).
func (s *GroupSchema) Can(assignments []GroupAssignment, custom CustomRoleResolver, perm string) bool {
	return anyGrantCovers(s.ResolveGrants(assignments, custom), perm)
}

// anyGrantCovers reports whether any grant token covers perm.
func anyGrantCovers(grants []string, perm string) bool {
	for _, g := range grants {
		if authbase.PermMatches(g, perm) {
			return true
		}
	}
	return false
}

func roleByName(roles []RoleDef, name string) (RoleDef, bool) {
	for _, r := range roles {
		if r.Name == name {
			return r, true
		}
	}
	return RoleDef{}, false
}
