package authkit_test

import (
	"reflect"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/stretchr/testify/require"
)

// The exact method list keeps Auth's public surface a deliberate choice:
// adding an operation means adding it here.
func TestAuthPublicSurface(t *testing.T) {
	typ := reflect.TypeOf((*authkit.Auth)(nil))
	var names []string
	for i := 0; i < typ.NumMethod(); i++ {
		names = append(names, typ.Method(i).Name)
	}
	require.ElementsMatch(t, []string{
		"APIKeys", "ActiveDeviceKeys", "ApplyBootstrapManifest", "AssignGroupRoles", "Ban", "Can", "CheckSMSHealth",
		"Close", "CreateAccountInvite", "CreateGroup", "CreateInviteLink", "CreateUser", "DefineGroupRole", "DeleteGroup",
		"DeleteGroupRole", "DeleteRemoteApplication", "DeleteUsers", "EffectivePermissions", "EnsureUserRole", "Group",
		"GroupRoles", "Groups", "Handler", "ImportSolanaLinks", "ImportUsers", "InviteLinks", "KnownPermission",
		"LinkProvider", "ListGroupMembers", "ListGroups", "ListSubjectGroups", "ListUsers", "MintAPIKey",
		"MintAccessToken", "MintDelegatedAccessToken", "MintRemoteApplicationAccessToken", "MintServiceJWT", "Mount",
		"NewVerifier", "Optional", "PatchUserMetadata", "Patterns", "PublicUsers", "PublishDocument", "PurgeGroup",
		"PurgeUsers", "RemoteApplication", "RemoteApplicationAuthority", "RemoteApplications", "RemoveGroupMembers",
		"Require", "RequireLive", "RequirePermission", "ResolveAPIKey", "RestoreUsers", "RevokeAPIKey",
		"RevokeAccountSessions", "RevokeInviteLink", "RevokeSession", "RiverJobs", "Routes", "Sessions", "SetEntitlements",
		"Start", "UnassignGroupRoles", "Unban", "UpdateGroup", "UpdateUser", "UpsertRemoteApplication", "User",
		"UserMetadata", "Users", "Verifier",
	}, names)
}
