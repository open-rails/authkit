package authkit_test

import (
	"context"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/apisurface"
	"github.com/open-rails/authkit/internal/ops"
	"github.com/stretchr/testify/require"
)

// TestGoAPISurface keeps api/go.txt, the Go API that v1 covers
// (docs/stability.md), equal to the exports of the covered packages. A
// removed or changed line is a break: only a minor release may ship it, listed in its notes; an added line is fine.
// Either way the change is deliberate: regenerate with go generate
// ./internal/httpapi and review the diff. The covered API may reach an
// internal type only through an alias a covered package declares.
func TestGoAPISurface(t *testing.T) {
	s, err := apisurface.Load()
	require.NoError(t, err)
	require.Empty(t, s.Leaks, "the covered API exposes internal types no covered package aliases")
	file, err := os.ReadFile(apisurface.File)
	require.NoError(t, err)
	listed := strings.Split(strings.TrimSuffix(string(file), "\n"), "\n")
	missing := func(from, in []string) []string {
		var out []string
		for _, line := range from {
			if !slices.Contains(in, line) {
				out = append(out, line)
			}
		}
		return out
	}
	if gone := missing(listed, s.Features); len(gone) > 0 {
		t.Errorf("removed or changed, a break for the release notes (%v):\n%s", apisurface.ErrStale, strings.Join(gone, "\n"))
	}
	if added := missing(s.Features, listed); len(added) > 0 {
		t.Errorf("added (%v):\n%s", apisurface.ErrStale, strings.Join(added, "\n"))
	}
	require.Equal(t, string(s.Text()), string(file), apisurface.ErrStale.Error())
}

// TestClientPublicSurface keeps Auth's surface a deliberate choice: every method
// is in exactly one of two lists. Methods whose rules depend on who acts take
// the acting iam.Actor right after ctx; host operations (your code decides),
// reads, lifecycle and HTTP take none. Every mutation and host operation ends
// in ...Option, and every method but the embedding-only ones is an operation
// of internal/ops.Operations with the same signature.
func TestClientPublicSurface(t *testing.T) {
	takesActor := []string{
		// Accounts and sessions.
		"UpdateUser", "PatchPublicMetadata", "Ban", "Unban", "DeleteUsers", "RestoreUsers",
		"RevokeSession", "RevokeAccountSessions",
		// Roles and checks.
		"SetGroupRole", "RemoveGroupMember", "Can", "EffectivePermissions",
		// Credentials and invitations.
		"CreateAPIKey", "RevokeAPIKey", "CreateInvitation", "RevokeInvitation",
		// Remote applications and delegation.
		"UpsertRemoteApplication", "DeleteRemoteApplication", "MintDelegatedAccessToken",
	}
	hostOperations := []string{
		"CreateUser", "PurgeUsers", "ResetAccountMFA", "MintAccessToken", "RevokeOAuthGrant",
		"CreateGroup", "DeleteGroup", "PurgeGroup",
		"ApplyBootstrapManifest", "EnsureUserRole", "ImportUsers", "ImportSolanaLinks", "LinkProvider",
		// Signing that grants no AuthKit authority.
		"MintServiceJWT",
	}
	reads := []string{
		// The host is the trust boundary.
		"User", "Users", "PublicUsers", "ListUsers", "ResolveUsername", "CheckUsername",
		"DeviceKeys", "Sessions", "ListSessionEvents",
		"Group", "Groups", "ListGroups", "ListGroupMembers", "ListMemberships", "GroupRoles", "KnownPermission",
		"ListAPIKeys", "ResolveAPIKey", "ListInvitations", "RemoteApplication", "ListRemoteApplications",
		"CheckSession", "CheckRecentSignIn",
		// Names read at run time, resolved through Config.Roles.
		"Persona", "Permission", "Role", "RolePermissions",
	}
	embeddingOnly := []string{
		// Lifecycle: host wiring at boot and health probes.
		"Start", "Close", "RiverJobs", "EmailAvailable", "EmailHealth", "SMSAvailable", "SMSHealth", "TwoFactorMethods",
		// HTTP surface and request verification.
		"Handler", "APIBase", "Routes", "Mount",
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
