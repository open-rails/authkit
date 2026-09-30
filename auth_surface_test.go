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

// TestClientPublicSurface keeps Auth's surface a deliberate choice: every method
// is in exactly one of two lists. Methods whose rules depend on who acts take
// the acting iam.Actor right after ctx; host operations (your code decides),
// reads, lifecycle and HTTP take none.
func TestClientPublicSurface(t *testing.T) {
	takesActor := []string{
		// Accounts and sessions.
		"UpdateUser", "PatchUserMetadata", "Ban", "Unban", "DeleteUsers", "RestoreUsers",
		"RevokeSession", "RevokeAccountSessions",
		// Roles and checks.
		"AssignGroupRoles", "UnassignGroupRoles", "RemoveGroupMembers",
		"Can", "EffectivePermissions",
		// Credentials and invitations.
		"MintAPIKey", "RevokeAPIKey", "CreateInviteLink", "RevokeInviteLink", "CreateAccountInvite",
		// Remote applications and delegation.
		"UpsertRemoteApplication", "DeleteRemoteApplication", "MintDelegatedAccessToken",
	}
	noActor := []string{
		// Host operations: your code decides.
		"CreateUser", "PurgeUsers", "ResetAccountMFA", "MintAccessToken",
		"CreateGroup", "DeleteGroup", "PurgeGroup",
		"ApplyBootstrapManifest", "EnsureUserRole", "ImportUsers", "ImportSolanaLinks", "LinkProvider",
		// Reads: the host is the trust boundary.
		"User", "Users", "PublicUsers", "ListUsers", "UserMetadata", "ResolveUsername", "CheckUsername",
		"ActiveDeviceKeys", "Sessions", "SessionEvents",
		"Group", "Groups", "ListGroups", "ListGroupMembers", "ListSubjectGroups", "GroupRoles", "KnownPermission",
		"APIKeys", "ResolveAPIKey", "InviteLinks",
		// Names read at run time, resolved through Config.Roles.
		"Persona", "Permission", "Role", "ParseBootstrapManifestYAML", "LoadBootstrapManifestFile",
		"RemoteApplication", "RemoteApplications", "RemoteApplicationAuthority",
		// Lifecycle: host wiring at boot and health probes.
		"SetEntitlements", "Start", "Close", "RiverJobs", "CheckSMSHealth",
		// HTTP surface and request verification (verify.Authority).
		"Handler", "Routes", "Patterns", "Mount",
		"VerifyRequest", "Verify", "VerifyServiceJWT", "AuthenticateRequest", "CheckSession", "CheckRecentSignIn",
		"CheckIssuerKeys", "IssuerKeyStatuses", "NewVerifier",
		// Signing that grants no AuthKit authority.
		"MintServiceJWT",
	}

	typ := reflect.TypeFor[*authkit.Client]()
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
			require.NotEqual(t, actorType, in, "%s takes an actor: list it in takesActor", name)
		}
	}
	for _, name := range names {
		require.False(t, strings.HasSuffix(name, "As") || strings.HasPrefix(name, "System"),
			"%s: the actor is a parameter, never part of the name", name)
	}
}
