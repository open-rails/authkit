package authkit

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

// The exact method list keeps Auth's public surface a deliberate choice:
// adding an operation means adding it here.
func TestAuthPublicSurface(t *testing.T) {
	typ := reflect.TypeOf((*Auth)(nil))
	var names []string
	for i := 0; i < typ.NumMethod(); i++ {
		names = append(names, typ.Method(i).Name)
	}
	require.ElementsMatch(t, []string{
		"ActiveDeviceKeys", "AdminGetUser", "AdminListUsers", "AdminRevokeAccountSessions", "AdminSetPassword",
		"AssignGroupRoles", "BanUser", "Can", "CanOnGroup", "CheckSMSHealth", "ClaimDPoPProof", "Close",
		"CreateGroupInviteLink", "CreatePermissionGroup", "CreateUser", "DelegatedPermissionLive",
		"DeleteGroupInstanceByID", "EffectivePermissionsForGroups", "GetRemoteApplication", "GetUserByEmail",
		"GetUserByPhone", "GetUserByUsername", "GetUserMetadata", "GroupInstanceByID", "GroupInstanceForSlug",
		"GroupInstancesByIDs", "GroupRoles", "Handler", "ImportUnverifiedSolanaLinks", "ImportUsers",
		"KnownPermission", "LinkProviderByIssuer", "ListAPIKeys", "ListEffectivePermissions",
		"ListGroupInviteLinks", "ListGroupMembers", "ListSubjectGroups", "MarkEmailVerified", "MintAccessToken",
		"MintAPIKey", "MintDelegatedAccessToken", "MintRemoteApplicationAccessToken", "MintServiceJWT", "Mount",
		"OperatorApplyBootstrapManifest", "OperatorRestoreUsers", "Optional", "Patterns", "PublicUsersByIDs",
		"RemoveGroupMembers", "Require", "RequireLive", "RequirePermission", "ResolveAPIKey",
		"ResolveGroupIDForSlug", "ResolveRemoteApplicationAuthority", "RevokeAPIKey", "RevokeGroupInviteLink",
		"RiverJobs", "Routes", "SetEntitlements", "SoftDeleteGroupInstanceByID", "SoftDeleteUsers", "Start",
		"UnassignGroupRoles", "UnbanUser", "UpdateAvatarURL", "UpdateEmail", "UpdateGroupInstanceAs",
		"UpdateImportedUser", "UpdateUsername", "UpsertPasswordHash", "UpsertRemoteApplication",
		"UserLivenessByIDs", "UsersByIDs", "Verifier",
	}, names)
}
