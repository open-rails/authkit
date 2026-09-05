package authkit

import "strings"

// Persona is a permission-group persona name (`root`, `org`, `merchant`): the
// first permission segment and the namespace every grant is anchored in.
type Persona string

// Role is a role slug in a persona's catalog (`owner`, `admin`) or a group's
// custom-role name.
type Role string

// Perm is a concrete permission (`org:members:read`) or a grant pattern
// (`org:members:*`, `org:*`).
type Perm string

// SubjectKind discriminates who holds a role in a permission group.
type SubjectKind string

const (
	SubjectKindUser      SubjectKind = "user"
	SubjectKindRemoteApp SubjectKind = "remote_application"

	// RootPersona is the single built-in persona: every deployment has exactly
	// one root group, the parentless ancestor of every other group.
	RootPersona Persona = "root"

	// OwnerRole is the role every persona ships: it holds the persona's whole
	// namespace (`<persona>:*`) and nothing else.
	OwnerRole Role = "owner"
)

// GroupRef addresses one permission-group instance: the persona plus its
// instance slug. The root group has no instance.
type GroupRef struct {
	Persona  Persona
	Instance string
}

// RootGroup addresses the deployment's root group.
func RootGroup() GroupRef { return GroupRef{Persona: RootPersona} }

func (g GroupRef) IsRoot() bool { return g.Persona == RootPersona }

func (g GroupRef) String() string {
	if g.Instance == "" {
		return string(g.Persona)
	}
	return string(g.Persona) + "/" + g.Instance
}

// Subject is a principal that can hold roles in a permission group.
type Subject struct {
	ID   string
	Kind SubjectKind
}

func UserSubject(id string) Subject      { return Subject{ID: id, Kind: SubjectKindUser} }
func RemoteAppSubject(id string) Subject { return Subject{ID: id, Kind: SubjectKindRemoteApp} }

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
