package iam

import (
	"fmt"
	"strings"
)

// The app declares its personas, permissions and roles once, with
// authkit.NewRoles, and passes those values around; a string never converts
// to one, so a misspelled name is a compile error. A name read at run time
// (a request parameter, a config file) goes through the schema: Client.Persona,
// Client.Permission and Client.Role. The text forms (MarshalText) are for wire
// formats; decoding one checks only its syntax.

// Persona is a type of permission group (`channel`, `org`, `merchant`). A
// permission group is one instance of a persona. root is the persona with
// exactly one group, the whole site. The persona is the first segment of
// every permission its groups use.
type Persona struct{ name string }

// RootPersona is the persona with exactly one group, the whole site. It
// always exists.
var RootPersona = Persona{"root"}

// String is the persona's name, "" for the zero Persona.
func (p Persona) String() string { return p.name }

func (p Persona) IsZero() bool { return p.name == "" }

// OwnerRole is the role every persona has: it holds the whole namespace,
// OwnerGrant, and nothing else.
func (p Persona) OwnerRole() Role { return Role{persona: p, name: ownerRoleName} }

// OwnerGrant is the owner's grant `<persona>:*`.
func (p Persona) OwnerGrant() Perm { return Perm{p.name + ":" + PermWildcard} }

func (p Persona) MarshalText() ([]byte, error) { return []byte(p.name), nil }

// UnmarshalText reads a persona name; empty is the zero Persona.
func (p *Persona) UnmarshalText(b []byte) error {
	s := string(b)
	if s != "" && !ValidPermissionSegment(s) {
		return fmt.Errorf("iam: persona %q must match [a-z][a-z0-9-]*", s)
	}
	*p = Persona{s}
	return nil
}

const ownerRoleName = "owner"

// Role is a role of a persona: its owner role, one the app declares
// (`moderator`), or a group's custom role. A role bundles permissions; where
// it is held is its scope, and a role held on root applies in every group. Its
// text form is `<persona>:<name>` (`channel:moderator`).
type Role struct {
	persona Persona
	name    string
}

// Persona is the persona whose groups the role is held in.
func (r Role) Persona() Persona { return r.persona }

// Name is the role's name within its persona (`moderator`).
func (r Role) Name() string { return r.name }

func (r Role) IsZero() bool { return r == Role{} }

// IsOwner reports whether r is its persona's owner role.
func (r Role) IsOwner() bool { return !r.persona.IsZero() && r.name == ownerRoleName }

// String is `<persona>:<name>`, "" for the zero Role.
func (r Role) String() string {
	if r.IsZero() {
		return ""
	}
	return r.persona.name + ":" + r.name
}

func (r Role) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

// UnmarshalText reads `<persona>:<name>`; empty is the zero Role.
func (r *Role) UnmarshalText(b []byte) error {
	s := string(b)
	if s == "" {
		*r = Role{}
		return nil
	}
	persona, name, ok := strings.Cut(s, ":")
	if !ok || !ValidPermissionSegment(persona) || !ValidPermissionSegment(name) {
		return fmt.Errorf("iam: role %q must be <persona>:<name>, each [a-z][a-z0-9-]*", s)
	}
	*r = Role{persona: Persona{persona}, name: name}
	return nil
}

// Perm is a permission `<persona>:<resource>:<action>` (`channel:posts:edit`)
// or a grant pattern, where `*` replaces the action (`channel:posts:*`) or
// everything after the persona (`channel:*`, the owner).
type Perm struct{ s string }

// String is the permission's text, "" for the zero Perm.
func (p Perm) String() string { return p.s }

func (p Perm) IsZero() bool { return p.s == "" }

func (p Perm) MarshalText() ([]byte, error) { return []byte(p.s), nil }

// UnmarshalText reads a permission or pattern: a persona, then a resource
// and an action, where `*` may stand for either, or `<persona>:*`. Empty is
// the zero Perm.
func (p *Perm) UnmarshalText(b []byte) error {
	s := string(b)
	if s != "" && !validPermText(s) {
		return fmt.Errorf("iam: permission %q must be <persona>:<resource>:<action> or a pattern over it", s)
	}
	*p = Perm{s}
	return nil
}

func validPermText(s string) bool {
	segs := strings.Split(s, ":")
	if !ValidPermissionSegment(segs[0]) {
		return false
	}
	switch len(segs) {
	case 2:
		return segs[1] == PermWildcard
	case 3:
		for _, seg := range segs[1:] {
			if seg != PermWildcard && !ValidPermissionSegment(seg) {
				return false
			}
		}
		return true
	}
	return false
}

// Grant is what a role holds: a permission or pattern, or another role of the
// same persona whose permissions it includes. Only Perm and Role are Grants.
type Grant interface{ grant() }

func (Perm) grant() {}
func (Role) grant() {}

// SubjectKind discriminates who holds a role in a permission group.
type SubjectKind string

const (
	SubjectKindUser              SubjectKind = "user"
	SubjectKindRemoteApplication SubjectKind = "remote_application"
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
	s, _, _ := strings.Cut(p.s, ":")
	return Persona{s}
}

// Matches reports whether grant authorizes this CONCRETE permission. The grant
// may be a literal (`org:members:read`) or a namespace-anchored glob where `*`
// wildcards a whole segment (`org:members:*`, `org:*:read`, `org:*`). The
// namespace (segment 0) must be a literal — a bare `*` (or a `*` namespace)
// never matches. A two-segment glob `ns:*` matches every concrete `ns:…` perm.
//
// This is the shared, authz-critical matcher used by both the engine's RBAC
// checks and the verification layer's permission-coverage checks.
func (p Perm) Matches(grant Perm) bool {
	g := strings.Split(strings.TrimSpace(grant.s), ":")
	c := strings.Split(strings.TrimSpace(p.s), ":")
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
