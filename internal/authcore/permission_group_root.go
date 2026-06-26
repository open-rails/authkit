package authcore

import "fmt"

// The intrinsic `root` catalog (#111): the authkit-OWNED permissions present in
// EVERY deployment — the former `platform:` namespace, renamed `root:` so the
// node and its namespace match (a one-time greenfield rename). These gate
// authkit's own identity/admin surface. Apps EXTEND the root catalog with their
// own moderation perms (doujins `root:content:takedown`, openrails
// `root:merchants:delete`) — declared as ordinary roles on the root persona.
//
// reach != capability: the root `owner` holds `root:*` — the widest REACH
// (ancestor of every group) but, being namespace-anchored, still
// moderation-only over the rest of the tree (it can never name a
// `merchant:`/`org:`/`repo:` perm).

const (
	// Operator dashboard visibility.
	PermRootResourcesRead = "root:resources:read" // read root/admin resources

	// Identity / account directory.
	PermRootUsersBan     = "root:users:ban"     // ban / unban an account
	PermRootUsersRecover = "root:users:recover" // recover a compromised account
	PermRootUsersDelete  = "root:users:delete"  // soft-delete / restore an account
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

// IntrinsicRootPersona returns the base `root` PersonaDef authkit ships: the
// parentless singleton persona. Its apex is the `owner` role (= root:*),
// auto-injected by normalizePersona.
// An app passes this to BuildSchema along with EXTRA root roles (bounded operator
// bundles like doujins's `admin`, which must NOT hold root:roles:manage if they
// shouldn't be able to promote) and its other personas; the extra root roles may
// hold any root: perm (intrinsic or app-declared). Custom roles are OFF on root
// (operators are not end users).
func IntrinsicRootPersona(extraRootRoles ...RoleDef) PersonaDef {
	return PersonaDef{
		Name:  RootPersona,
		Roles: extraRootRoles, // owner (root:*) is auto-injected by normalizePersona
		// Parent empty ⇒ parentless singleton (the only such persona).
	}
}

// BuildSchema assembles the deployment's GroupSchema from authkit's intrinsic
// root persona plus the app's declared personas, and validates the whole. Root
// declarations are additive: apps may pass root roles, catalog entries, or
// capabilities without redefining authkit's intrinsic root. Non-root persona
// names remain globally unique and are rejected by NewGroupSchema.
func BuildSchema(appTypes ...PersonaDef) (*GroupSchema, error) {
	root := IntrinsicRootPersona()
	rootCapabilitySet := false
	types := make([]PersonaDef, 0, len(appTypes)+1)
	for _, t := range appTypes {
		if t.Name == RootPersona {
			if t.Parent != "" {
				return nil, fmt.Errorf("group persona %q: root persona must not declare a parent", RootPersona)
			}
			root.Roles = append(root.Roles, t.Roles...)
			root.Catalog = append(root.Catalog, t.Catalog...)
			if !personaCapabilitiesZero(t.Capabilities) {
				if rootCapabilitySet {
					return nil, fmt.Errorf("group persona %q: capabilities may be set by only one root declaration", RootPersona)
				}
				root.Capabilities = t.Capabilities
				rootCapabilitySet = true
			}
			continue
		}
		types = append(types, t)
	}
	types = append([]PersonaDef{root}, types...)
	return NewGroupSchema(types...)
}

func personaCapabilitiesZero(c PersonaCapabilities) bool {
	return !c.APIKeys && !c.RemoteApplications && !c.CustomRoles
}
