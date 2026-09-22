package embedded

import (
	"errors"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

type httpBuildFunc func(HTTPBackend) (HTTPSurface, error)

func (f httpBuildFunc) BuildHTTP(r HTTPBackend) (HTTPSurface, error) { return f(r) }

type testHTTPSurface struct {
	routes   []HTTPRoute
	closed   atomic.Int32
	verifier *verify.Verifier
}

func (s *testHTTPSurface) Routes() []HTTPRoute        { return s.routes }
func (s *testHTTPSurface) Verifier() *verify.Verifier { return s.verifier }
func (s *testHTTPSurface) Close()                     { s.closed.Add(1) }

func TestRuntimeClientOwnsNoLocalResources(t *testing.T) {
	runtime := &engine{}
	client := runtime.Client()
	var _ authkit.Client = client
	require.NotNil(t, client)
	typ := reflect.TypeOf(client)
	for _, name := range []string{"Close", "Start", "Postgres", "Config", "Schema", "JWKS", "Genesis", "RiverJobs", "ConfigureHTTP", "SetEntitlementsProvider", "EnsureRootGroup", "SeedPermissionGroupContainment", "ApplyBootstrapManifest", "HasEmailSender", "HasSMSSender", "SMSAvailable", "CheckSMSHealth", "CleanupExpiredAuthState", "ValidateVerificationConfiguration", "ExternalInvitesEnabled"} {
		_, ok := typ.MethodByName(name)
		require.False(t, ok, "operation Client exposes runtime method %s", name)
	}
	require.Nil(t, (*engine)(nil).Client())
}

func TestRuntimeHTTPSealsBeforeBuilderSideEffects(t *testing.T) {
	for _, state := range []string{"configured", "inspected", "closed", "failed"} {
		t.Run(state, func(t *testing.T) {
			runtime := &engine{}
			count := 0
			surface := &testHTTPSurface{routes: []HTTPRoute{{Method: http.MethodGet, Path: "/one", Handler: http.NotFoundHandler()}}, verifier: verify.NewVerifier()}
			build := httpBuildFunc(func(HTTPBackend) (HTTPSurface, error) {
				count++
				if state == "failed" {
					return surface, errors.New("failed build")
				}
				return surface, nil
			})
			switch state {
			case "configured":
				require.NoError(t, runtime.ConfigureHTTP(build))
				require.Same(t, surface.verifier, runtime.Verifier())
				routes, err := runtime.HTTPRoutes()
				require.NoError(t, err)
				routes[0].Path = "/mutated"
				again, err := runtime.HTTPRoutes()
				require.NoError(t, err)
				require.Equal(t, "/one", again[0].Path)
			case "inspected":
				_, err := runtime.HTTPRoutes()
				require.Error(t, err)
			case "closed":
				runtime.Close()
			case "failed":
				require.ErrorContains(t, runtime.ConfigureHTTP(build), "failed build")
				require.EqualValues(t, 1, surface.closed.Load())
			}
			before := count
			require.Error(t, runtime.ConfigureHTTP(build))
			require.Equal(t, before, count, "rejected configuration ran builder")
			runtime.Close()
			runtime.Close()
			require.Nil(t, runtime.Verifier())
			_, err := runtime.HTTPRoutes()
			require.Error(t, err)
			if state == "configured" || state == "failed" {
				require.EqualValues(t, 1, surface.closed.Load())
			}
		})
	}
}

func TestRuntimeConcurrentConfigureAndClose(t *testing.T) {
	runtime := &engine{}
	surface := &testHTTPSurface{}
	started, finish := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = runtime.ConfigureHTTP(httpBuildFunc(func(HTTPBackend) (HTTPSurface, error) { close(started); <-finish; return surface, nil }))
	}()
	<-started
	go func() { defer wg.Done(); runtime.Close() }()
	close(finish)
	wg.Wait()
	require.EqualValues(t, 1, surface.closed.Load())
	require.Error(t, runtime.ConfigureHTTP(httpBuildFunc(func(HTTPBackend) (HTTPSurface, error) { t.Fatal("closed runtime invoked builder"); return nil, nil })))
}

// Exact allowlist prevents a convenient business/resource accessor from slowly
// turning Runtime back into an application service.
func TestRuntimePublicSurface(t *testing.T) {
	typ := reflect.TypeOf((*Runtime)(nil))
	var names []string
	for i := 0; i < typ.NumMethod(); i++ {
		names = append(names, typ.Method(i).Name)
	}
	require.ElementsMatch(t, []string{"Client", "Close", "Start", "RiverJobs", "ConfigureHTTP", "HTTPRoutes", "Verifier", "SetEntitlementsProvider"}, names)
	runtime := &Runtime{engine: &engine{}}
	require.NotNil(t, runtime.Client())
	require.Nil(t, (*Runtime)(nil).Client())
}
