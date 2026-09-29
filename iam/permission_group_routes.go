package iam

// Built-in per-persona group-management permissions (authkit-provisioned in
// every persona's catalog). All are 3-segment <persona>:<area>:<action>. The owner
// role (=<persona>:*) covers them all; an app may grant them to other roles.
func PermMembersManage(p Persona) Perm {
	return Perm(string(p) + ":members:manage")
}

func PermMembersRead(p Persona) Perm {
	return Perm(string(p) + ":members:read")
}

func PermRolesManage(p Persona) Perm {
	return Perm(string(p) + ":roles:manage")
}

func PermRolesRead(p Persona) Perm { return Perm(string(p) + ":roles:read") }

func PermCredentialsManage(p Persona) Perm {
	return Perm(string(p) + ":credentials:manage")
}

func PermCredentialsRead(p Persona) Perm {
	return Perm(string(p) + ":credentials:read")
}

// PermSettingsManage gates the group's own settings surface (#264): slug
// rename and display-name changes. Held by the owner via `<persona>:*`;
// grant it to other roles deliberately.
func PermSettingsManage(p Persona) Perm {
	return Perm(string(p) + ":settings:manage")
}

// PermSettingsRead gates reading the group's own identity descriptor (#269):
// GET /<persona>/:instance_slug — id, slug, display name. The read symmetric of
// PermSettingsManage; held by the owner via `<persona>:*`.
func PermSettingsRead(p Persona) Perm {
	return Perm(string(p) + ":settings:read")
}
