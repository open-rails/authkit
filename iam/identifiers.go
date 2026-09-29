package iam

import "strings"

// Persona names a type of permission group (`channel`, `org`, `merchant`). A
// permission group is one instance of a persona (/c/golang). root is the
// persona with exactly one group, the whole site. The persona is the first
// segment of every permission its groups use.
type Persona string

// Role names a role of a persona (`owner`, `moderator`) or a group's custom
// role. A role bundles permissions; where it is held is its scope, and a role
// held on root applies in every group.
type Role string

// Perm is a permission `<persona>:<resource>:<action>` (`channel:posts:edit`)
// or a grant pattern, where `*` replaces the action (`channel:posts:*`) or
// everything after the persona (`channel:*`, the owner). The resource `self`
// is the group itself.
type Perm string

// SubjectKind discriminates who holds a role in a permission group.
type SubjectKind string

const (
	SubjectKindUser              SubjectKind = "user"
	SubjectKindRemoteApplication SubjectKind = "remote_application"

	// RootPersona is the built-in persona with exactly one group, the whole
	// site. It always exists.
	RootPersona Persona = "root"

	// OwnerRole is the role every persona ships: it holds the persona's whole
	// namespace (`<persona>:*`) and nothing else.
	OwnerRole Role = "owner"
)

// Subject is a principal that can hold roles in a permission group.
type Subject struct {
	ID   string
	Kind SubjectKind
}

func UserSubject(id string) Subject { return Subject{ID: id, Kind: SubjectKindUser} }
func RemoteApplicationSubject(id string) Subject {
	return Subject{ID: id, Kind: SubjectKindRemoteApplication}
}

// PermWildcard is the wildcard CHARACTER used inside namespace-anchored globs
// (`org:*`, `org:members:*`, `org:*:read`, `root:*`). A bare standalone `*`
// is NOT a valid grant — it is rejected everywhere.
const PermWildcard = "*"

// Persona returns the permission's first segment: its namespace.
func (p Perm) Persona() Persona {
	s := string(p)
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return Persona(s[:i])
	}
	return Persona(s)
}

// OwnerGrant is the namespace-pure owner grant for a persona: `<persona>:*`.
func (p Persona) OwnerGrant() Perm { return Perm(string(p) + ":" + PermWildcard) }

// Matches reports whether grant authorizes this CONCRETE permission. The grant
// may be a literal (`org:members:read`) or a namespace-anchored glob where `*`
// wildcards a whole segment (`org:members:*`, `org:*:read`, `org:*`). The
// namespace (segment 0) must be a literal — a bare `*` (or a `*` namespace)
// never matches. A two-segment glob `ns:*` matches every concrete `ns:…` perm.
//
// This is the shared, authz-critical matcher used by both the engine's RBAC
// checks and the verification layer's permission-coverage checks.
func (p Perm) Matches(grant Perm) bool {
	g := strings.Split(strings.TrimSpace(string(grant)), ":")
	c := strings.Split(strings.TrimSpace(string(p)), ":")
	if g[0] == "" || g[0] == PermWildcard {
		return false // namespace must be a literal prefix (namespace-anchored)
	}
	// Two-segment namespace-wide glob: `ns:*` covers every `ns:<resource>:<action>`.
	if len(g) == 2 && g[1] == PermWildcard {
		return c[0] == g[0]
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
