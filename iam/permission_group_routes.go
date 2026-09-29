package iam

// SelfResource is the permission resource meaning the group itself
// (`channel:self:update`). It is reserved to AuthKit's built-ins.
const SelfResource = "self"

// Built-in per-persona permissions. AuthKit registers them in every persona's
// catalog; the owner role (`<persona>:*`) covers them all, and an app may grant
// them to other roles.
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

// PermSelfRead gates reading the group's own descriptor: id, slug, display name.
func PermSelfRead(p Persona) Perm { return Perm(string(p) + ":self:read") }

// PermSelfUpdate gates changing the group's slug and display name.
func PermSelfUpdate(p Persona) Perm { return Perm(string(p) + ":self:update") }

// PermSelfDelete gates the recoverable (soft) delete of the group.
func PermSelfDelete(p Persona) Perm { return Perm(string(p) + ":self:delete") }

// BuiltinPermissions returns the permissions AuthKit registers for persona p.
// Root has no `self` permissions (its group cannot be read, renamed or
// deleted as a group) and adds IntrinsicRootPermissions.
func BuiltinPermissions(p Persona) []Perm {
	out := []Perm{
		PermMembersRead(p), PermMembersManage(p),
		PermRolesRead(p), PermRolesManage(p),
		PermCredentialsRead(p), PermCredentialsManage(p),
	}
	if p == RootPersona {
		for _, perm := range IntrinsicRootPermissions() {
			out = append(out, Perm(perm))
		}
		return out
	}
	return append(out, PermSelfRead(p), PermSelfUpdate(p), PermSelfDelete(p))
}
