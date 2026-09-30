package ident

import "github.com/open-rails/authkit/iam"

// The built-in permissions of every persona, and the root permissions every
// deployment registers. Hosts get them from authkit.NewRoles
// (rbac.Channel.Members.Read); these serve AuthKit's own code, which knows a
// persona only at run time.

// MembersRead gates listing a group's members and its role catalog.
func MembersRead(p iam.Persona) iam.Perm { return Perm(p.String() + ":members:read") }

// MembersManage gates adding, removing and re-roling members and invitations.
func MembersManage(p iam.Persona) iam.Perm { return Perm(p.String() + ":members:manage") }

// CredentialsRead gates listing API keys. Registered only for personas with
// API keys or remote applications.
func CredentialsRead(p iam.Persona) iam.Perm { return Perm(p.String() + ":credentials:read") }

// CredentialsManage gates creating, revoking and re-roling API keys and
// remote applications. Registered with CredentialsRead.
func CredentialsManage(p iam.Persona) iam.Perm { return Perm(p.String() + ":credentials:manage") }

// The intrinsic root permissions gating AuthKit's account administration.
var (
	RootUsersRead   = Perm("root:users:read")   // list and read accounts and their sign-ins
	RootUsersBan    = Perm("root:users:ban")    // ban / unban an account
	RootUsersDelete = Perm("root:users:delete") // soft-delete and restore an account
	RootUsersManage = Perm("root:users:manage") // edit another account, revoke its sessions
	RootUsersInvite = Perm("root:users:invite") // invite someone to create an account
)

// IntrinsicRootPermissions are the root permissions every deployment
// registers besides the members built-ins.
func IntrinsicRootPermissions() []iam.Perm {
	return []iam.Perm{RootUsersRead, RootUsersBan, RootUsersDelete, RootUsersManage, RootUsersInvite}
}
