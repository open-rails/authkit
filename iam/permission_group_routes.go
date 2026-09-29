package iam

// Built-in per-persona permissions. The owner role (`<persona>:*`) covers
// them all, and an app may grant them to other roles.

// PermMembersRead gates listing a group's members and its role catalog.
func PermMembersRead(p Persona) Perm { return Perm(string(p) + ":members:read") }

// PermMembersManage gates adding, removing and re-roling members and invites.
func PermMembersManage(p Persona) Perm { return Perm(string(p) + ":members:manage") }

// PermRolesManage gates defining and deleting custom roles. Registered only
// for personas with CustomRoles.
func PermRolesManage(p Persona) Perm { return Perm(string(p) + ":roles:manage") }

// PermCredentialsRead gates listing API keys and remote applications.
// Registered only for personas with APIKeys or RemoteApplications.
func PermCredentialsRead(p Persona) Perm { return Perm(string(p) + ":credentials:read") }

// PermCredentialsManage gates minting, revoking and re-roling API keys and
// remote applications. Registered with PermCredentialsRead.
func PermCredentialsManage(p Persona) Perm { return Perm(string(p) + ":credentials:manage") }
