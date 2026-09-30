package authkit_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ops"
	"github.com/stretchr/testify/require"
)

// TestClientPublicSurface keeps Auth's surface a deliberate choice: every method
// is in exactly one of two lists. Methods whose rules depend on who acts take
// the acting iam.Actor right after ctx; host operations (your code decides),
// reads, lifecycle and HTTP take none. Every mutation and host operation ends
// in ...Option, and every method but the embedding-only ones is an operation
// of internal/ops.Operations with the same signature.
func TestClientPublicSurface(t *testing.T) {
	takesActor := []string{
		// Accounts and sessions.
		"UpdateUser", "PatchUserMetadata", "Ban", "Unban", "DeleteUsers", "RestoreUsers",
		"RevokeSession", "RevokeAccountSessions",
		// Roles and checks.
		"SetGroupRole", "RemoveGroupMember", "Can", "EffectivePermissions",
		// Credentials and invitations.
		"CreateAPIKey", "RevokeAPIKey", "CreateInvitation", "RevokeInvitation",
		// Remote applications and delegation.
		"UpsertRemoteApplication", "DeleteRemoteApplication", "MintDelegatedAccessToken",
	}
	hostOperations := []string{
		"CreateUser", "PurgeUsers", "ResetAccountMFA", "MintAccessToken",
		"CreateGroup", "DeleteGroup", "PurgeGroup",
		"ApplyBootstrapManifest", "EnsureUserRole", "ImportUsers", "ImportSolanaLinks", "LinkProvider",
		// Signing that grants no AuthKit authority.
		"MintServiceJWT",
	}
	reads := []string{
		// The host is the trust boundary.
		"User", "Users", "PublicUsers", "ListUsers", "UserMetadata", "ResolveUsername", "CheckUsername",
		"DeviceKeys", "Sessions", "ListSessionEvents",
		"Group", "Groups", "ListGroups", "ListGroupMembers", "ListMemberships", "GroupRoles", "KnownPermission",
		"ListAPIKeys", "ResolveAPIKey", "ListInvitations", "RemoteApplication", "ListRemoteApplications",
		"CheckSession", "CheckRecentSignIn",
		// Names read at run time, resolved through Config.Roles.
		"Persona", "Permission", "Role", "ParseBootstrapManifestYAML",
	}
	embeddingOnly := []string{
		// Lifecycle: host wiring at boot and health probes.
		"Start", "Close", "RiverJobs", "SMSAvailable", "SMSHealth",
		// HTTP surface and request verification.
		"Handler", "Routes", "Mount",
		"VerifyRequest", "Verify", "VerifyServiceJWT", "AuthenticateRequest",
		"CheckIssuerKeys", "IssuerKeyStatuses", "NewVerifier",
	}
	noActor := append(append(append([]string{}, hostOperations...), reads...), embeddingOnly...)

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

	optionType := reflect.TypeFor[[]authkit.Option]()
	for _, name := range append(append([]string{"User"}, takesActor...), hostOperations...) {
		if name == "Can" || name == "EffectivePermissions" {
			continue
		}
		m, _ := typ.MethodByName(name)
		require.True(t, m.Type.IsVariadic(), "%s ends in ...Option", name)
		require.Equal(t, optionType, m.Type.In(m.Type.NumIn()-1), "%s ends in ...Option", name)
	}

	opsType := reflect.TypeFor[ops.Operations]()
	var opNames []string
	for m := range opsType.Methods() {
		opNames = append(opNames, m.Name)
		cm, ok := typ.MethodByName(m.Name)
		require.True(t, ok, "Client lacks operation %s", m.Name)
		require.Equal(t, m.Type.NumIn()+1, cm.Type.NumIn(), m.Name)
		for i := range m.Type.NumIn() {
			require.Equal(t, m.Type.In(i), cm.Type.In(i+1), "%s parameter %d", m.Name, i)
		}
		require.Equal(t, m.Type.NumOut(), cm.Type.NumOut(), m.Name)
		for i := range m.Type.NumOut() {
			require.Equal(t, m.Type.Out(i), cm.Type.Out(i), "%s result %d", m.Name, i)
		}
	}
	require.ElementsMatch(t, append(append(append([]string{}, takesActor...), hostOperations...), reads...), opNames,
		"every method but the embedding-only ones is an ops.Operations operation")
}
