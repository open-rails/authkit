package authkit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync/atomic"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/engine"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/verify"
	riverhelpers "github.com/open-rails/helpers/river"
)

// Auth is AuthKit embedded in a host: the engine, its verifier and, when
// Config.HTTP is set, its HTTP surface. Build it with New, wire any
// entitlements cycle with SetEntitlements, then Start it. Operations are
// methods, grouped by domain in the auth_*.go files.
type Auth struct {
	engine      *engine.Engine
	verifier    *verify.Verifier
	requireLive func(http.Handler) http.Handler
	http        *httpapi.Service
	mount       *httpapi.Mount
	started     atomic.Bool
}

// Auth is what verify's permission, liveness and delegation seams consume.
var (
	_ verify.LivenessSource     = (*Auth)(nil)
	_ verify.Authority          = (*Auth)(nil)
	_ verify.DelegatedAuthority = (*Auth)(nil)
)

// New builds AuthKit from host configuration and dependencies. Run Migrate on
// the pool first.
func New(cfg Config, deps Deps) (_ *Auth, err error) {
	settings := cfg.settings()
	e, err := engine.New(settings.engine, deps.engine())
	if err != nil {
		return nil, err
	}
	a := &Auth{engine: e, verifier: e.Verifier()}
	defer func() {
		if err != nil {
			a.Close()
		}
	}()
	if a.requireLive, err = verify.RequiredLive(a.verifier); err != nil {
		return nil, err
	}
	if settings.http != nil {
		if deps.Postgres == nil {
			return nil, errors.New("authkit: HTTP requires Deps.Postgres")
		}
		if a.http, a.mount, err = newHTTP(e, a.verifier, *settings.http); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// newHTTP builds the HTTP layer and its one mounted handler.
func newHTTP(e *engine.Engine, v *verify.Verifier, cfg httpapi.Config) (*httpapi.Service, *httpapi.Mount, error) {
	svc, err := httpapi.New(e, v, cfg)
	if err != nil {
		return nil, nil, err
	}
	mount, err := httpapi.NewMount(svc, cfg.Mount)
	if err != nil {
		svc.Close()
		return nil, nil, err
	}
	return svc, mount, nil
}

// SetEntitlements installs the entitlements provider after New, for a host
// whose provider needs this Auth first (a billing engine that authenticates
// through it). Hosts without that cycle set Deps.Entitlements. It must precede
// Start.
func (a *Auth) SetEntitlements(provider EntitlementsProvider) error {
	if a.started.Load() {
		return errors.New("authkit: SetEntitlements after Start")
	}
	a.engine.SetEntitlements(provider)
	return nil
}

// Start starts AuthKit's background work (account lifecycle, auth-state
// cleanup). Call it once, after wiring and before serving.
func (a *Auth) Start(ctx context.Context) error {
	a.started.Store(true)
	return a.engine.Start(ctx)
}

// RiverJobs contributes AuthKit's jobs to a host-owned River fleet
// (Deps.River = RiverFromHost()).
func (a *Auth) RiverJobs() riverhelpers.Contribution { return a.engine.RiverJobs() }

// Close releases AuthKit-owned resources. Host-owned dependencies stay open.
func (a *Auth) Close() {
	if a == nil {
		return
	}
	a.http.Close()
	a.engine.Close()
}

// CheckSMSHealth probes, without sending, whether the SMS sender can deliver
// and records the verdict that gates phone flows. Register it as a recurring
// dependency probe; every call re-records.
func (a *Auth) CheckSMSHealth(ctx context.Context) error { return a.engine.CheckSMSHealth(ctx) }

// Handler serves AuthKit's whole HTTP surface; nil when Config.HTTP is nil.
// Mount it at the host root: it owns its anchored paths.
func (a *Auth) Handler() http.Handler {
	if a.mount == nil {
		return nil
	}
	return a.mount
}

// Routes returns the mounted route catalog, with a HEAD entry per GET route.
func (a *Auth) Routes() []iam.Route { return a.mount.Routes() }

// Patterns returns the mounted routes as net/http ServeMux patterns
// ("GET /api/v1/me"), sorted. A GET pattern also serves HEAD.
func (a *Auth) Patterns() []string {
	var out []string
	for _, route := range a.mount.Routes() {
		if route.Method == http.MethodHead {
			continue
		}
		out = append(out, route.Method+" "+route.Path)
	}
	sort.Strings(out)
	return out
}

// Mount registers every pattern on mux, all served by Handler.
func (a *Auth) Mount(mux *http.ServeMux) (err error) {
	if a.mount == nil {
		return errors.New("authkit: HTTP is not configured; set Config.HTTP")
	}
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("authkit: mount: %v", p)
		}
	}()
	for _, pattern := range a.Patterns() {
		mux.Handle(pattern, a.mount)
	}
	return nil
}

// Verifier verifies requests and tokens against this deployment. It exists
// from New on, with or without an HTTP surface.
func (a *Auth) Verifier() *verify.Verifier { return a.verifier }

// Require rejects requests without a valid credential. Ordinary
// verification is stateless; see RequireLive.
func (a *Auth) Require(next http.Handler) http.Handler { return verify.Required(a.verifier)(next) }

// Optional verifies a credential when one is presented.
func (a *Auth) Optional(next http.Handler) http.Handler { return verify.Optional(a.verifier)(next) }

// RequireLive is Require plus a live account check for sensitive operations.
func (a *Auth) RequireLive(next http.Handler) http.Handler { return a.requireLive(next) }
