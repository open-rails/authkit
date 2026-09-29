package iam

// The intrinsic `root` permissions: present in every deployment, they gate
// AuthKit's own account administration. Apps add their own root permissions
// (`root:content:takedown`) with authkit.Roles.Root.Permission.
var (
	PermRootUsersRead   = Perm{"root:users:read"}   // list and read accounts and their sign-ins
	PermRootUsersBan    = Perm{"root:users:ban"}    // ban / unban an account
	PermRootUsersDelete = Perm{"root:users:delete"} // soft-delete and restore an account
	PermRootUsersManage = Perm{"root:users:manage"} // edit another account, revoke its sessions
	PermRootUsersInvite = Perm{"root:users:invite"} // invite someone to create an account
)

// IntrinsicRootPermissions returns the root permissions every deployment
// registers besides the members built-ins.
func IntrinsicRootPermissions() []Perm {
	return []Perm{PermRootUsersRead, PermRootUsersBan, PermRootUsersDelete, PermRootUsersManage, PermRootUsersInvite}
}
