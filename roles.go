package authkit

import "github.com/open-rails/authkit/iam"

// RoleConfig declares who may do what, read once at New.
//
// A persona is a type of permission group (channel, org, merchant). A
// permission group is one instance of a persona (/c/golang), created at run
// time. root is the persona with exactly one group, the whole site; it always
// exists and needs no entry. A permission is `<persona>:<resource>:<action>`;
// `*` may replace the action (`channel:posts:*`) or everything after the
// persona (`channel:*`, the owner). The resource `self` is the group itself.
type RoleConfig struct {
	// Personas maps each persona name to its settings. A "root" entry is
	// optional and only adds app-specific root permissions and capabilities.
	Personas map[string]Persona
	// Roles are bundles of permissions. Each lives in the groups of one
	// persona. Every persona also gets an `owner` role holding `<persona>:*`.
	Roles []Role
}

// Persona holds one persona's settings.
type Persona struct {
	// Permissions is the persona's complete app-defined catalog, each
	// `<persona>:<resource>:<action>`. AuthKit adds its own built-ins
	// (members, roles, credentials and, except on root, self).
	Permissions []string
	// RequireMFA lists catalog permissions (or patterns over the catalog)
	// that need a second factor. A subject holding a grant that reaches one,
	// through any role, include or root role, must have MFA enrolled, and no
	// API key may hold it. root:members:manage always needs MFA.
	RequireMFA []string
	// Creation opts the persona into POST /<persona>.
	Creation GroupCreation
	// CustomRoles lets group owners define roles at run time, composed from
	// the persona's catalog.
	CustomRoles bool
	// APIKeys mounts the group API-key routes.
	APIKeys bool
	// RemoteApplications mounts the group remote-application routes.
	RemoteApplications bool
}

// GroupCreation opts a persona into POST /<persona>: any signed-in user may
// create a group and becomes its owner.
type GroupCreation struct {
	Enabled bool
	// SlugPattern further restricts slugs beyond the built-in rule: an
	// unanchored regexp, anchored at New.
	SlugPattern string
	// ReservedSlugs are creatable only by actors holding `<persona>:*` on root.
	ReservedSlugs []string
}

// Role is a named bundle of permissions held in groups of one persona. A root
// role (Persona: iam.RootPersona) applies in every group and may hold any
// persona's permissions; any other role holds only its own persona's.
type Role struct {
	Persona     iam.Persona
	Name        iam.Role
	Permissions []string
	// Includes names roles of the same persona whose permissions this role
	// also holds.
	Includes []iam.Role
}
