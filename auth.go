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

// Client is AuthKit embedded in a host: the engine and, unless Config.HTTP
// is zero, its HTTP surface. Build it with New, wire any entitlements cycle
// with SetEntitlements, then Start it. Operations are methods, grouped by
// domain in the auth_*.go files. It is the authority verify's middleware
// takes: verify.Required(client), verify.RequirePermission(client, perm).
type Client struct {
	engine  *engine.Engine
	http    *httpapi.Service
	mount   *httpapi.Mount
	started atomic.Bool
}

var _ verify.Authority = (*Client)(nil)

// New builds AuthKit from host configuration and dependencies. Run Migrate on
// the pool first. ctx bounds the boot-time database work.
func New(ctx context.Context, cfg Config, deps Deps) (_ *Client, err error) {
	if err := cfg.Roles.err(); err != nil {
		return nil, fmt.Errorf("authkit: Config.Roles: %w", err)
	}
	settings := cfg.settings()
	e, err := engine.New(ctx, settings.engine, deps.engine())
	if err != nil {
		return nil, err
	}
	a := &Client{engine: e}
	defer func() {
		if err != nil {
			a.Close()
		}
	}()
	if settings.http != nil {
		if deps.Postgres == nil {
			return nil, errors.New("authkit: HTTP requires Deps.Postgres")
		}
		if a.http, a.mount, err = newHTTP(e, *settings.http); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// newHTTP builds the HTTP layer and its one mounted handler.
func newHTTP(e *engine.Engine, cfg httpapi.Config) (*httpapi.Service, *httpapi.Mount, error) {
	svc, err := httpapi.New(e, cfg)
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
// whose provider needs this Client first (a billing engine that authenticates
// through it). Hosts without that cycle set Deps.Entitlements. It must precede
// Start.
func (a *Client) SetEntitlements(provider EntitlementsProvider) error {
	if a.started.Load() {
		return errors.New("authkit: SetEntitlements after Start")
	}
	a.engine.SetEntitlements(provider)
	return nil
}

// Start starts AuthKit's background work (account lifecycle, auth-state
// cleanup). Call it once, after wiring and before serving.
func (a *Client) Start(ctx context.Context) error {
	a.started.Store(true)
	return a.engine.Start(ctx)
}

// RiverJobs contributes AuthKit's jobs to a host-owned River fleet
// (Deps.River = RiverFromHost()).
func (a *Client) RiverJobs() riverhelpers.Contribution { return a.engine.RiverJobs() }

// Close releases AuthKit-owned resources. Host-owned dependencies stay open.
func (a *Client) Close() {
	if a == nil {
		return
	}
	a.http.Close()
	a.engine.Close()
}

// CheckSMSHealth probes, without sending, whether the SMS sender can deliver
// and records the verdict that gates phone flows. Register it as a recurring
// dependency probe; every call re-records.
func (a *Client) CheckSMSHealth(ctx context.Context) error { return a.engine.CheckSMSHealth(ctx) }

// Handler serves AuthKit's whole HTTP surface; nil when Config.HTTP is zero.
// Mount it at the host root: its paths already include HTTPConfig.BasePath.
func (a *Client) Handler() http.Handler {
	if a.mount == nil {
		return nil
	}
	return a.mount
}

// Routes returns the mounted route catalog, with a HEAD entry per GET route.
func (a *Client) Routes() []iam.Route { return a.mount.Routes() }

// Patterns returns the mounted routes as net/http ServeMux patterns
// ("GET /api/v1/me"), full paths beneath HTTPConfig.BasePath, sorted. A GET
// pattern also serves HEAD.
func (a *Client) Patterns() []string {
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
func (a *Client) Mount(mux *http.ServeMux) (err error) {
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
