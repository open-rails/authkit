package authcore

// The intrinsic `root` catalog (#111): the authkit-OWNED permissions present in
// EVERY deployment — the former `platform:` namespace, renamed `root:` so the
// node and its namespace match (a one-time greenfield rename). These gate
// authkit's own identity/admin surface. Apps EXTEND the root catalog with their
// own moderation perms (doujins `root:content:takedown`, openrails
// `root:merchants:delete`) — declared as ordinary roles on the root type.
//
// reach != capability: the root `owner` holds `root:*` (super-admin) — the
// widest REACH (ancestor of every group) but, being namespace-anchored, still
// moderation-only over the rest of the tree (it can never name a
// `merchant:`/`org:`/`repo:` perm).

const (
	// Identity / account directory.
	PermRootUsersRead    = "root:users:read"    // read the account directory
	PermRootUsersSuspend = "root:users:suspend" // suspend / unsuspend an account
	PermRootUsersBan     = "root:users:ban"     // ban / unban an account
	PermRootUsersUpdate  = "root:users:update"  // update account identity/password fields
	PermRootUsersDelete  = "root:users:delete"  // soft-delete / restore an account

	// Group lifecycle as ENTITIES (moderation — delete/restore a group, never run it).
	PermRootGroupsCreate = "root:groups:create" // create a top-level group as an operator
	PermRootGroupsDelete = "root:groups:delete" // soft-delete / restore any group

	// Operator management of roles/credentials/sessions.
	PermRootRolesManage      = "root:roles:manage"       // define/inspect platform-operator roles
	PermRootRemoteAppsManage = "root:remote-apps:manage" // manage federation issuers as an operator
	PermRootAPIKeysRevoke    = "root:api-keys:revoke"    // revoke any api-key
	PermRootSessionsRevoke   = "root:sessions:revoke"    // revoke any user session

	// SuperAdminRoleName is the root role authkit ships in addition to owner:
	// the apex operator. Like owner it holds root:* (they are equivalent on the
	// root type); kept as a distinct name for the familiar "super-admin" slug.
	SuperAdminRoleName = "super-admin"
)

// IntrinsicRootPermissions returns the authkit-built-in root: permission set
// (every deployment ships these). Apps add their own root: moderation perms on
// top via the root type's roles.
func IntrinsicRootPermissions() []string {
	return []string{
		PermRootUsersRead, PermRootUsersSuspend, PermRootUsersBan, PermRootUsersUpdate, PermRootUsersDelete,
		PermRootGroupsCreate, PermRootGroupsDelete,
		PermRootRolesManage, PermRootRemoteAppsManage, PermRootAPIKeysRevoke, PermRootSessionsRevoke,
	}
}

// IntrinsicRootPersona returns the base `root` PersonaDef authkit ships: the
// parentless singleton type whose owner/super-admin hold root:*. An app passes
// this to BuildSchema along with EXTRA root roles (moderation bundles) and its
// other types; the extra root roles may hold any root: perm (intrinsic or
// app-declared). Custom roles are OFF on root (operators are not end users).
func IntrinsicRootPersona(extraRootRoles ...RoleDef) PersonaDef {
	roles := make([]RoleDef, 0, len(extraRootRoles)+1)
	// super-admin == root:* (owner is also seeded = root:* by normalizePersona).
	roles = append(roles, RoleDef{Name: SuperAdminRoleName, Permissions: []string{OwnerGrant(RootPersona)}})
	roles = append(roles, extraRootRoles...)
	return PersonaDef{
		Name:  RootPersona,
		Roles: roles,
		// AllowedParents empty ⇒ parentless singleton (the only such type).
		Routes: ManagementProfile{MemberAssignment: true}, // operators are assigned root roles via API
	}
}

// BuildSchema assembles the deployment's GroupSchema from authkit's intrinsic
// root type plus the app's declared types, and validates the whole. If the app
// passes its OWN root type (to add moderation roles) it is used as-is; otherwise
// the bare IntrinsicRootPersona() is injected. This is the consumer entry point:
// an app declares only its non-root types (+ optional extra root roles) and gets
// a validated schema, or a clear error.
func BuildSchema(appTypes ...PersonaDef) (*GroupSchema, error) {
	hasRoot := false
	for _, t := range appTypes {
		if t.Name == RootPersona {
			hasRoot = true
			break
		}
	}
	types := appTypes
	if !hasRoot {
		types = append([]PersonaDef{IntrinsicRootPersona()}, appTypes...)
	}
	return NewGroupSchema(types...)
}
