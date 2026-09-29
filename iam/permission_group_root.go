package iam

// The intrinsic `root` permissions: present in every deployment, they gate
// AuthKit's own account administration. Apps add their own root permissions
// (`root:content:takedown`) through the optional root persona entry.
const (
	PermRootUsersRead   = "root:users:read"   // list and read accounts and their sign-ins
	PermRootUsersBan    = "root:users:ban"    // ban / unban an account
	PermRootUsersDelete = "root:users:delete" // soft-delete and restore an account
	PermRootUsersManage = "root:users:manage" // edit another account, revoke its sessions
	PermRootUsersInvite = "root:users:invite" // invite someone to create an account
)

// IntrinsicRootPermissions returns the root permissions every deployment
// registers besides the members built-ins.
func IntrinsicRootPermissions() []string {
	return []string{PermRootUsersRead, PermRootUsersBan, PermRootUsersDelete, PermRootUsersManage, PermRootUsersInvite}
}
