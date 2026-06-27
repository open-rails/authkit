package authkit

import "strings"

// PermWildcard is the wildcard CHARACTER used inside namespace-anchored globs
// (`org:*`, `org:members:*`, `org:*:read`, `root:*`). A bare standalone `*`
// is NOT a valid grant — it is rejected everywhere.
const PermWildcard = "*"

// PermMatches reports whether a GRANT token authorizes a CONCRETE permission.
// The grant may be a literal (`org:members:read`) or a namespace-anchored glob
// where `*` wildcards a whole segment (`org:members:*`, `org:*:read`, `org:*`).
// The namespace (segment 0) must be a literal — a bare `*` (or a `*` namespace)
// never matches. A two-segment glob `ns:*` matches every concrete `ns:…` perm.
//
// This is the shared, authz-critical matcher used by both core's RBAC checks and
// the verification layer's permission-coverage checks.
func PermMatches(grant, concrete string) bool {
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
