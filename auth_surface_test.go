package authkit_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

// TestAuthPublicSurface keeps Auth's surface a deliberate choice: a new method
// must be placed in one of these lists. Every mutation and every check takes
// the acting iam.Actor right after ctx; nothing else takes an actor.
func TestAuthPublicSurface(t *testing.T) {
	takesActor := []string{
		// Accounts, sessions and tokens.
		"CreateUser", "UpdateUser", "PatchUserMetadata", "Ban", "Unban", "DeleteUsers", "RestoreUsers", "PurgeUsers",
		"ResetAccountMFA", "RevokeSession", "RevokeAccountSessions", "MintAccessToken",
		// Groups, roles and checks.
		"CreateGroup", "UpdateGroup", "DeleteGroup", "PurgeGroup", "AssignGroupRoles", "UnassignGroupRoles",
		"RemoveGroupMembers", "DefineGroupRole", "DeleteGroupRole", "Can", "EffectivePermissions",
		// Credentials and invitations.
		"MintAPIKey", "RevokeAPIKey", "CreateInviteLink", "RevokeInviteLink", "CreateAccountInvite",
		// Remote applications and delegation.
		"UpsertRemoteApplication", "DeleteRemoteApplication", "MintDelegatedAccessToken",
		// Bootstrap and import (operator only).
		"ApplyBootstrapManifest", "EnsureUserRole", "ImportUsers", "ImportSolanaLinks", "LinkProvider",
	}
	noActor := []string{
		// Reads: the host is the trust boundary.
		"User", "Users", "PublicUsers", "ListUsers", "UserMetadata", "ActiveDeviceKeys", "Sessions",
		"Group", "Groups", "ListGroups", "ListGroupMembers", "ListSubjectGroups", "OwnerlessGroups", "GroupRoles", "KnownPermission",
		"APIKeys", "ResolveAPIKey", "InviteLinks",
		"RemoteApplication", "RemoteApplications", "RemoteApplicationAuthority",
		// Lifecycle: host wiring at boot and health probes.
		"SetEntitlements", "Start", "Close", "RiverJobs", "CheckSMSHealth", "PublishDocument",
		// HTTP surface and request verification.
		"Handler", "Routes", "Patterns", "Mount", "Verifier", "NewVerifier",
		"Require", "Optional", "RequireLive", "RequirePermission",
		// Signing that grants no AuthKit authority.
		"MintServiceJWT", "MintRemoteApplicationAccessToken",
	}

	typ := reflect.TypeFor[*authkit.Auth]()
	var names []string
	for m := range typ.Methods() {
		names = append(names, m.Name)
	}
	require.ElementsMatch(t, append(append([]string{}, takesActor...), noActor...), names)

	ctxType, actorType := reflect.TypeFor[context.Context](), reflect.TypeFor[iam.Actor]()
	for _, name := range takesActor {
		m, _ := typ.MethodByName(name)
		require.GreaterOrEqual(t, m.Type.NumIn(), 3, name)
		require.Equal(t, ctxType, m.Type.In(1), "%s: ctx comes first", name)
		require.Equal(t, actorType, m.Type.In(2), "%s: the actor follows ctx", name)
	}
	for _, name := range noActor {
		m, _ := typ.MethodByName(name)
		for in := range m.Type.Ins() {
			if in.Kind() == reflect.Slice {
				in = in.Elem()
			}
			require.NotEqual(t, actorType, in, "%s takes an actor: list it with the operations", name)
		}
	}
	for _, name := range names {
		require.False(t, strings.HasSuffix(name, "As") || strings.HasPrefix(name, "Operator"),
			"%s: the actor is a parameter, never part of the name", name)
	}
}
