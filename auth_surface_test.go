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
		"APIKeys", "ActiveDeviceKeys", "AdminGetUser", "AdminListUsers", "AdminRevokeAccountSessions", "AdminSetPassword",
		"AssignGroupRoles", "BanUser", "Can", "CheckSMSHealth", "Close", "CreateAccountInvite",
		"CreateGroup", "CreateInviteLink", "CreateUser", "DefineGroupRole", "DeleteGroup",
		"DeleteGroupRole", "EffectivePermissions", "EnsureUserRole", "GetUserByEmail", "GetUserByPhone",
		"GetUserByUsername", "GetUserMetadata", "Group", "GroupRoles", "Groups", "Handler", "ImportSolanaLinks",
		"ImportUsers", "InviteLinks", "KnownPermission", "LinkProvider", "ListGroupMembers", "ListGroups",
		"ListSubjectGroups", "MarkEmailVerified", "MintAPIKey", "MintAccessToken", "MintDelegatedAccessToken",
		"MintRemoteApplicationAccessToken", "MintServiceJWT", "Mount", "ApplyBootstrapManifest",
		"OperatorRestoreUsers", "Optional", "Patterns", "PublicUsersByIDs", "PurgeGroup", "RemoveGroupMembers", "Require",
		"RequireLive", "RequirePermission", "ResolveAPIKey", "RevokeAPIKey",
		"RevokeInviteLink", "RiverJobs", "Routes", "SetEntitlements", "SoftDeleteUsers", "Start", "UnassignGroupRoles",
		"UnbanUser", "UpdateAvatarURL", "UpdateEmail", "UpdateGroup", "UpdateUsername",
		"UpsertPasswordHash", "UpsertRemoteApplication", "UserLivenessByIDs", "UsersByIDs", "Verifier",
		"DeleteRemoteApplication", "NewVerifier", "PublishDocument", "RemoteApplication", "RemoteApplicationAuthority",
		"RemoteApplications",
	}, names)
}
