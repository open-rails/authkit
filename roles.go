package authkit

import "github.com/open-rails/authkit/internal/config"

// The permission model's builder, defined in internal/config.
type (
	// Roles is the app's permission model: its personas, their permissions
	// and their roles. Declare it once and pass it as Config.Roles.
	Roles           = config.Roles
	PersonaDef      = config.PersonaDef
	RootDef         = config.RootDef
	Resource        = config.Resource
	MemberPerms     = config.MemberPerms
	CredentialPerms = config.CredentialPerms
	DirectoryPerms  = config.DirectoryPerms
	RolePerms       = config.RolePerms
	UserPerms       = config.UserPerms
	PersonaOption   = config.PersonaOption
)

// Persona capabilities.
const (
	// APIKeys mounts the group API-key routes. It registers Credentials.
	APIKeys = config.APIKeys
	// RemoteApplications lets the persona's groups control remote
	// applications. It registers Credentials.
	RemoteApplications = config.RemoteApplications
	// CustomRoles lets the persona's groups define roles of their own. It
	// registers Roles.
	CustomRoles = config.CustomRoles
	// OAuthClients lets the persona's groups register OAuth clients that
	// sign their users in, with consent. It registers Credentials.
	OAuthClients = config.OAuthClients
)

// NewRoles starts a permission model holding only root; opts switch on root's
// capabilities.
func NewRoles(opts ...PersonaOption) *Roles { return config.NewRoles(opts...) }
