package authkit

import "github.com/open-rails/authkit/internal/httpapi"

// testRuntime is the Auth the HTTP workflow tests drive; setup the public
// surface does not offer goes through its engine.
type testRuntime = Auth

func newTestRuntime(cfg Config, deps Deps) (*testRuntime, error) { return New(cfg, deps) }

// fixtureBackend is the engine behind an HTTP service.
func fixtureBackend(b httpapi.Backend) *engine { return b.(*engine) }

func newTestService(r *testRuntime, cfg httpapi.Config) (*httpapi.Service, error) {
	return httpapi.New(r.engine, r.Verifier(), cfg)
}
