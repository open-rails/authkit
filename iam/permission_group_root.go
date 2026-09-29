package iam

// The intrinsic `root` permissions: present in every deployment, they gate
// AuthKit's own identity and admin surface. Apps add their own root
// permissions (`root:content:takedown`) through the optional root persona entry.
const (
	// Operator dashboard visibility.
	PermRootResourcesRead = "root:resources:read" // read root/admin resources

	// Identity / account directory.
	PermRootUsersBan     = "root:users:ban"     // ban / unban an account
	PermRootUsersRecover = "root:users:recover" // revoke every session of an account
	PermRootUsersDelete  = "root:users:delete"  // soft-delete an account
	// PermRootUsersInvite authorizes minting a STANDALONE account-registration
	// invite (#147): inviting someone to create an account, independent of any
	// permission-group invite. owner holds it via root:*; hosts may grant it to a
	// bounded operator role so non-owner staff can invite new accounts.
	PermRootUsersInvite = "root:users:invite" // invite someone to create an account

	// Operator management of roles/credentials.
	PermRootRolesManage       = "root:roles:manage"       // define/inspect platform-operator roles
	PermRootCredentialsManage = "root:credentials:manage" // manage/revoke machine credentials as an operator
)

// IntrinsicRootPermissions returns the authkit-built-in root: permission set
// (every deployment ships these). Apps add their own root: moderation perms on
// top via the root persona's roles.
func IntrinsicRootPermissions() []string {
	return []string{
		PermRootResourcesRead,
		PermRootUsersBan, PermRootUsersRecover, PermRootUsersDelete, PermRootUsersInvite,
		PermRootRolesManage, PermRootCredentialsManage,
	}
}
