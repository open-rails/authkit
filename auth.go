package authkit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/builtwith"
	"github.com/open-rails/authkit/internal/engine"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/ops"
	"github.com/open-rails/authkit/internal/testclock"
	"github.com/open-rails/authkit/verify"
	riverhelpers "github.com/open-rails/helpers/river"
	"github.com/riverqueue/river"
)

// Client is AuthKit embedded in a host: the engine and, when Config.HTTP is
// set, its HTTP surface. Build it with New, then Start it. Operations are
// methods, grouped by domain in the auth_*.go files. It is the authority
// verify's middleware takes: verify.Required(client),
// verify.RequirePermission(client, perm).
//
// Start, Close, RiverJobs, EmailAvailable, EmailHealth, SMSAvailable,
// SMSHealth, TwoFactorMethods, Handler, APIBase, Routes, Mount and the request
// verification methods
// (auth_verify.go) are embedding-only:
// they wire the in-process deployment, and a Client of a remote deployment
// would not have them. Every other method is an operation a remote
// deployment could serve.
type Client struct {
	ops    ops.Operations
	engine *engine.Engine
	http   *httpapi.Service
	mount  *httpapi.Mount
	// cfg and deps are what New was given (internal/builtwith).
	cfg  Config
	deps Deps
	// noMerchant logs once that RequirePermission refuses everything.
	noMerchant sync.Once
}

func init() {
	builtwith.Of = func(client any) (Config, Deps, bool) {
		a, ok := client.(*Client)
		if !ok || a == nil {
			return Config{}, Deps{}, false
		}
		return a.cfg, a.deps, true
	}
	testclock.Use = func(client any, now func() time.Time) { client.(*Client).engine.SetClock(now) }
}

var _ verify.Authority = (*Client)(nil)

// New builds AuthKit from host configuration and dependencies. Run Migrate on
// the pool first. ctx bounds the boot-time database work.
func New(ctx context.Context, cfg Config, deps Deps) (_ *Client, err error) {
	e, err := engine.New(ctx, cfg, deps)
	if err != nil {
		return nil, err
	}
	a := &Client{ops: e, engine: e, cfg: cfg, deps: deps}
	defer func() {
		if err != nil {
			_ = a.Close(context.WithoutCancel(ctx))
		}
	}()
	if group := e.Config().Merchant.Group; group != "" {
		root, err := e.RootGroupID(ctx)
		if err != nil {
			return nil, err
		}
		if group == root {
			return nil, errors.New("authkit: Config.Merchant.Group is the root group; set Config.Merchant.Root to check merchant staff there")
		}
	}
	if e.Config().HTTP != nil {
		if a.http, a.mount, err = newHTTP(e, deps); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// newHTTP builds the HTTP layer and its one mounted handler.
func newHTTP(e *engine.Engine, deps Deps) (*httpapi.Service, *httpapi.Mount, error) {
	svc, err := httpapi.New(e, e.Config(), deps)
	if err != nil {
		return nil, nil, err
	}
	mount, err := httpapi.NewMount(svc)
	if err != nil {
		svc.Close()
		return nil, nil, err
	}
	return svc, mount, nil
}

// StartOption configures Start.
type StartOption func(*startOptions)

type startOptions struct {
	fleet    *river.Client[pgx.Tx]
	hostOwns bool
}

// WithRiverClient runs AuthKit's jobs on the host's River fleet, which
// riverhelpers.New built with RiverJobs in Config.RiverSchema. AuthKit enqueues
// through it and never starts or stops it.
func WithRiverClient(fleet *river.Client[pgx.Tx]) StartOption {
	return func(o *startOptions) { o.fleet, o.hostOwns = fleet, true }
}

// Start starts AuthKit's background work: River (account lifecycle, events,
// auth-state cleanup) and the senders' health checks. With no options it
// builds and runs AuthKit's own River client in Config.RiverSchema; with
// WithRiverClient the jobs run on the host's fleet. Jobs queued before Start
// wait for it. Call it once, before serving.
func (a *Client) Start(ctx context.Context, opts ...StartOption) error {
	var o startOptions
	for _, opt := range opts {
		opt(&o)
	}
	if o.hostOwns && o.fleet == nil {
		return errors.New("authkit: WithRiverClient requires a River client")
	}
	return a.engine.Start(ctx, o.fleet)
}

// RiverJobs contributes AuthKit's jobs to the host's River fleet: compose it
// with riverhelpers.New, then pass that fleet to Start with WithRiverClient.
func (a *Client) RiverJobs() riverhelpers.Contribution { return a.engine.RiverJobs() }

// Close stops what Start started and releases AuthKit's own resources; ctx
// bounds stopping its own River client. The host's pool and River fleet stay
// open.
func (a *Client) Close(ctx context.Context) error {
	if a == nil {
		return nil
	}
	a.http.Close()
	return a.engine.Close(ctx)
}

// EmailAvailable reports whether email flows are offered: Deps.Email is set
// and its latest health check, if any, passed.
func (a *Client) EmailAvailable() bool { return a.engine.EmailAvailable() }

// EmailHealth is the latest Deps.Email.CheckHealth verdict and when it ran
// (Start runs it every Config.SenderHealthInterval); a zero time means no
// check has run.
func (a *Client) EmailHealth() (checkedAt time.Time, err error) { return a.engine.EmailHealth() }

// SMSAvailable is EmailAvailable for Deps.SMS and phone flows.
func (a *Client) SMSAvailable() bool { return a.engine.SMSAvailable() }

// SMSHealth is EmailHealth for Deps.SMS.
func (a *Client) SMSHealth() (checkedAt time.Time, err error) { return a.engine.SMSHealth() }

// TwoFactorMethods are the second factors a user can enroll now, as GET
// /capabilities lists them: enabled by Config.TwoFactor, with their
// dependency present (Deps.Email and Deps.SMS while healthy, the TOTP key).
// Empty when 2FA is disabled.
func (a *Client) TwoFactorMethods() []iam.TwoFactorMethod { return a.engine.TwoFactorMethods() }

// Handler serves AuthKit's whole HTTP surface; nil when Config.HTTP is zero.
// Mount it at the host root: its paths already include HTTPConfig.BasePath.
func (a *Client) Handler() http.Handler {
	if a.mount == nil {
		return nil
	}
	return a.mount
}

// APIBase is the path the JSON API is served at: {BasePath}{APIPath}/v1,
// "/api/v1" by default. It is "" without Config.HTTP.
func (a *Client) APIBase() string { return a.mount.APIBase() }

// Routes returns the mounted route catalog, with a HEAD entry per GET route;
// Route.Pattern is its net/http ServeMux pattern.
func (a *Client) Routes() []iam.Route { return a.mount.Routes() }

// Mount registers every route's pattern on mux (a GET pattern also serves
// HEAD), all served by Handler.
func (a *Client) Mount(mux *http.ServeMux) (err error) {
	if a.mount == nil {
		return errors.New("authkit: HTTP is not configured; set Config.HTTP")
	}
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("authkit: mount: %v", p)
		}
	}()
	for _, route := range a.mount.Routes() {
		if route.Method != http.MethodHead {
			mux.Handle(route.Pattern(), a.mount)
		}
	}
	return nil
}
