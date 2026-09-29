package authkit

import (
	"reflect"
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

func TestRuntimeClientOwnsNoLocalResources(t *testing.T) {
	runtime := &engine{}
	client := runtime.Client()
	var _ iam.Client = client
	require.NotNil(t, client)
	typ := reflect.TypeOf(client)
	for _, name := range []string{"Close", "Start", "Postgres", "Config", "Schema", "JWKS", "Genesis", "RiverJobs", "ConfigureHTTP", "SetEntitlementsProvider", "EnsureRootGroup", "SeedPermissionGroupContainment", "ApplyBootstrapManifest", "HasEmailSender", "HasSMSSender", "SMSAvailable", "CheckSMSHealth", "CleanupExpiredAuthState", "ValidateVerificationConfiguration", "ExternalInvitesEnabled"} {
		_, ok := typ.MethodByName(name)
		require.False(t, ok, "operation Client exposes runtime method %s", name)
	}
	require.Nil(t, (*engine)(nil).Client())
}

// Exact allowlist prevents a convenient business/resource accessor from slowly
// turning Runtime back into an application service.
func TestRuntimePublicSurface(t *testing.T) {
	typ := reflect.TypeOf((*Runtime)(nil))
	var names []string
	for i := 0; i < typ.NumMethod(); i++ {
		names = append(names, typ.Method(i).Name)
	}
	require.ElementsMatch(t, []string{"Client", "Close", "Start", "RiverJobs", "Verifier", "SetEntitlementsProvider", "Handler", "Routes", "Patterns", "Mount", "Require", "Optional", "RequireLive", "CheckSMSHealth"}, names)
	runtime := &Runtime{engine: &engine{}}
	require.NotNil(t, runtime.Client())
	require.Nil(t, (*Runtime)(nil).Client())
}
