package config

import (
	"errors"
	"fmt"
	"slices"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/rbac"
)

// Roles is the app's permission model: its personas, their permissions and
// their roles. Every declaration returns a typed value (iam.Persona, iam.Perm,
// iam.Role) that the app then passes to AuthKit, so a misspelled name is a
// compile error, not a silent deny. Declare it once, typically in a
// package-level var block, and pass it as Config.Roles. New reads it and
// reports every declaration error; changes after New have no effect.
//
// A persona is a type of permission group (channel, org, merchant). A
// permission group is one instance of a persona, created at run time by the
// host (Client.CreateGroup) for an entity of its own, such as the channel
// /c/golang. root is the persona with exactly one group, the whole site; it
// always exists. A permission is `<persona>:<resource>:<action>`; `*` may
// replace the action (`channel:posts:*`) or everything after the persona
// (`channel:*`, the owner).
type Roles struct {
	// Root is the persona with exactly one group, the whole site. A role held
	// on root applies in every group and may hold any persona's permissions.
	Root     *RootDef
	personas []*PersonaDef
	roles    []rbac.RoleSpec
	errs     []error
}

// NewRoles starts a permission model holding only root; opts switch on root's
// capabilities.
func NewRoles(opts ...PersonaOption) *Roles {
	r := &Roles{}
	r.Root = &RootDef{PersonaDef: r.persona(iam.RootPersona(), opts)}
	r.Root.Users = UserPerms{
		Resource: r.Root.Resource("users"),
		Read:     ident.RootUsersRead,
		Ban:      ident.RootUsersBan,
		Delete:   ident.RootUsersDelete,
		Manage:   ident.RootUsersManage,
		Invite:   ident.RootUsersInvite,
	}
	return r
}

// PersonaOption switches on a persona capability.
type PersonaOption uint8

const (
	// APIKeys mounts the group API-key routes. It registers Credentials.
	APIKeys PersonaOption = iota + 1
	// RemoteApplications lets the persona's groups control remote
	// applications (Client.UpsertRemoteApplication). It registers Credentials.
	RemoteApplications
)

// Persona declares a persona and returns its definition. name is the first
// segment of every permission of its groups: `[a-z][a-z0-9-]*`.
func (r *Roles) Persona(name string, opts ...PersonaOption) *PersonaDef {
	p := ident.Persona(name)
	switch {
	case p.IsZero():
		r.errorf("persona %q: name must match [a-z][a-z0-9-]*", name)
	case p == iam.RootPersona():
		r.errorf("persona %q always exists: use Roles.Root", name)
	default:
		for _, d := range r.personas {
			if d.Persona == p {
				r.errorf("persona %q declared twice", name)
			}
		}
	}
	return r.persona(p, opts)
}

func (r *Roles) persona(p iam.Persona, opts []PersonaOption) *PersonaDef {
	d := &PersonaDef{Persona: p, Owner: p.OwnerRole(), roles: r, spec: rbac.PersonaSpec{Name: p}, declared: map[iam.Perm]bool{}}
	for _, o := range opts {
		switch o {
		case APIKeys:
			d.spec.APIKeys = true
		case RemoteApplications:
			d.spec.RemoteApplications = true
		default:
			r.errorf("persona %q: unknown option %d", p, o)
		}
	}
	d.Members = MemberPerms{Resource: d.Resource("members"), Read: ident.MembersRead(p), Manage: ident.MembersManage(p)}
	d.Credentials = CredentialPerms{Resource: d.Resource("credentials"), Read: ident.CredentialsRead(p), Manage: ident.CredentialsManage(p)}
	r.personas = append(r.personas, d)
	return d
}

func (r *Roles) errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Errorf(format, args...))
}

// PersonaDef is one declared persona: the permissions and roles of its
// groups. AuthKit registers the built-in permission fields: Members always,
// Credentials with APIKeys or RemoteApplications. A role holding one that is
// not registered fails New.
type PersonaDef struct {
	Persona iam.Persona
	// Owner is the role every persona has: it holds All(). Root's also holds
	// every other persona's All(). A group's creator can be seeded with it
	// (iam.NewGroup.Owner).
	Owner       iam.Role
	Members     MemberPerms
	Credentials CredentialPerms

	roles    *Roles
	spec     rbac.PersonaSpec
	declared map[iam.Perm]bool
}

// Permission declares the permission `<persona>:<resource>:<action>` and
// returns it.
func (p *PersonaDef) Permission(resource, action string) iam.Perm {
	perm := ident.Perm(p.Persona.String() + ":" + resource + ":" + action)
	switch {
	case !ident.ValidSegment(resource) || !ident.ValidSegment(action):
		p.roles.errorf("persona %q permission %q:%q: each segment must match [a-z][a-z0-9-]*", p.Persona, resource, action)
		return iam.Perm{}
	case p.builtIn(perm):
		p.roles.errorf("permission %q is built in", perm)
	case p.declared[perm]:
		p.roles.errorf("permission %q declared twice", perm)
	default:
		p.declared[perm] = true
		p.spec.Permissions = append(p.spec.Permissions, perm)
	}
	return perm
}

func (p *PersonaDef) builtIn(perm iam.Perm) bool {
	return slices.Contains(rbac.Builtins(p.Persona, true), perm)
}

// Resource is one resource of the persona, for the pattern over all its
// actions.
func (p *PersonaDef) Resource(name string) Resource {
	if !ident.ValidSegment(name) {
		p.roles.errorf("persona %q resource %q: name must match [a-z][a-z0-9-]*", p.Persona, name)
	}
	return Resource{persona: p.Persona, name: name}
}

// All is `<persona>:*`: every permission of the persona.
func (p *PersonaDef) All() iam.Perm { return p.Persona.OwnerGrant() }

// Role declares a role held in the persona's groups and returns it. Each grant
// is a permission or pattern (Resource.All, All), or a role of this persona
// whose permissions the new role includes. A persona role holds only its own
// persona's permissions; a root role may hold any persona's, and applies in
// every group of that persona.
func (p *PersonaDef) Role(name string, grants ...iam.Grant) iam.Role {
	role := ident.Role(p.Persona, name)
	switch {
	case role.IsZero():
		p.roles.errorf("persona %q role %q: name must match [a-z][a-z0-9-]*", p.Persona, name)
		return iam.Role{}
	case role == p.Owner:
		p.roles.errorf("persona %q: the %q role is built in: use Owner", p.Persona, name)
		return role
	}
	def := rbac.RoleSpec{Name: role}
	for _, g := range grants {
		switch g := g.(type) {
		case iam.Perm:
			if g.IsZero() {
				p.roles.errorf("persona %q role %q: a grant is the zero permission", p.Persona, name)
				continue
			}
			def.Grants = append(def.Grants, g)
		case iam.Role:
			if g.Persona() != p.Persona {
				p.roles.errorf("persona %q role %q includes %q, a role of another persona", p.Persona, name, g)
				continue
			}
			def.Includes = append(def.Includes, g)
		}
	}
	p.roles.roles = append(p.roles.roles, def)
	return role
}

// RequireMFA marks permissions, or patterns over the persona's catalog, that
// need a second factor: a subject holding a grant that reaches one, through
// any role, include or root role, must have MFA enrolled, and no API key or
// application may hold it. root:members:manage and root:users:manage always
// need MFA.
func (p *PersonaDef) RequireMFA(perms ...iam.Perm) {
	p.spec.RequireMFA = append(p.spec.RequireMFA, perms...)
}

// RootDef is root: a persona, plus the account administration permissions
// AuthKit registers on it.
type RootDef struct {
	*PersonaDef
	Users UserPerms
}

// Resource is one resource of a persona.
type Resource struct {
	persona iam.Persona
	name    string
}

// All is `<persona>:<resource>:*`: every action on the resource.
func (r Resource) All() iam.Perm {
	return ident.Perm(r.persona.String() + ":" + r.name + ":" + iam.PermWildcard)
}

// MemberPerms are a persona's built-in membership permissions.
type MemberPerms struct {
	Resource
	Read   iam.Perm // see who holds which role, and the role catalog
	Manage iam.Perm // give someone a role, change it or take it away; invites
}

// CredentialPerms are the credential permissions, registered with APIKeys or
// RemoteApplications.
type CredentialPerms struct {
	Resource
	Read   iam.Perm // list the group's API keys
	Manage iam.Perm // mint, revoke and re-role them
}

// UserPerms are root's account administration permissions.
type UserPerms struct {
	Resource
	Read   iam.Perm // look through accounts and their sign-in history
	Ban    iam.Perm // ban and unban
	Delete iam.Perm // delete an account, or restore it within its 30 days
	Manage iam.Perm // edit someone else's account and sign them out everywhere
	Invite iam.Perm // invite someone to create an account
}

// CompileRoles checks the declared model and compiles it, once, into the
// schema the engine authorizes against; nil is root-only.
func CompileRoles(r *Roles) (*rbac.Schema, error) {
	if r == nil {
		return rbac.Default(), nil
	}
	if err := errors.Join(r.errs...); err != nil {
		return nil, fmt.Errorf("authkit: Config.Roles: %w", err)
	}
	personas := make([]rbac.PersonaSpec, 0, len(r.personas))
	for _, p := range r.personas {
		if !p.Persona.IsZero() {
			personas = append(personas, p.spec)
		}
	}
	s, err := rbac.New(personas, r.roles)
	if err != nil {
		return nil, fmt.Errorf("authkit: Config.Roles: %w", err)
	}
	return s, nil
}
