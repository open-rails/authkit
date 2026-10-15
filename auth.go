package authkit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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
// Start, Close, RiverJobs, Ready, Probes, EmailAvailable, EmailHealth,
// SMSAvailable, SMSHealth, TwoFactorMethods, Handler, APIBase, Routes, Mount
// and the request verification methods (auth_verify.go) are embedding-only:
// they wire the in-process deployment, and a Client of a remote deployment
// would not have them. Every other method is an operation a remote
// deployment could serve.
type Client struct {
	ops    ops.Operations
	engine *engine.Engine
	http   *httpapi.Service
	mount  *httpapi.Mount
	// cfg and deps are what New was given (internal/builtwith).
	cfg      Config
	deps     Deps
	tenantID iam.TenantID
	borrowed bool
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

// New builds AuthKit from host configuration and dependencies. It first
// creates or upgrades AuthKit's and River's tables (Config.Database) through
// Deps.Postgres, whose role owns them, waiting up to 30 seconds for PostgreSQL
// to answer; replicas booting together are safe, and a schema a newer build
// already migrated boots unchanged. ctx bounds the boot-time database work.
// Database.SkipMigrations validates the existing migration ledgers instead;
// use Migrate explicitly before starting such an application.
//
// New fails only when AuthKit cannot run safely: PostgreSQL unreachable or
// its migrations failing, no usable signing key, or configuration it cannot
// interpret without risking a weaker posture. A misconfigured or unreachable
// optional dependency (an identity provider, a remote application, a sender,
// Redis) is logged and switches off only what needs it; Probes reports it.
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
	if e.Config().HTTP != nil {
		if a.http, a.mount, err = newHTTP(e, deps); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// newHTTP builds the HTTP layer and its one mounted handler, serving the
// identity providers the engine kept.
func newHTTP(e *engine.Engine, deps Deps) (*httpapi.Service, *httpapi.Mount, error) {
	deps.Providers = e.Providers()
	svc, err := httpapi.New(e, e.Config(), deps)
	if err != nil {
		return nil, nil, err
	}
	e.SetSMSLimiter(svc.Limiter())
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
// riverhelpers.New built with RiverJobs in Config.Database.RiverSchema. AuthKit enqueues
// through it and never starts or stops it.
func WithRiverClient(fleet *river.Client[pgx.Tx]) StartOption {
	return func(o *startOptions) { o.fleet, o.hostOwns = fleet, true }
}

// Start starts AuthKit's background work: River (account lifecycle, events,
// auth-state cleanup) and the senders' health checks. With no options it
// builds and runs AuthKit's own River client in Config.Database.RiverSchema; with
// WithRiverClient the jobs run on the host's fleet. Jobs queued before Start
// wait for it. Call it once, before serving.
func (a *Client) Start(ctx context.Context, opts ...StartOption) error {
	if a.borrowed {
		return errors.New("authkit: start the owning client, not a tenant view")
	}
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
	if a.borrowed {
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

// Probe checks one optional dependency or degraded feature (Client.Probes).
type Probe = engine.Probe

// Ready reports whether AuthKit can serve: PostgreSQL answers, River runs
// (AuthKit's own since Start, or the host's fleet bound to RiverJobs), and a
// signing deployment holds an active key. Optional dependencies never fail
// it; see Probes.
func (a *Client) Ready(ctx context.Context) error { return a.engine.Ready(ctx) }

// Probes lists AuthKit's optional dependencies and degraded features for the
// host's dependency supervisor. None fails Ready: while one fails, only the
// features that need it are refused. authkit_config fails while a survivable
// configuration problem is in force (each was logged at New and switched off
// or defaulted only what it concerns); authkit_email and authkit_sms report
// the senders' latest health checks; authkit_redis pings Deps.Redis (limits
// and spent DPoP proofs are per process while it fails); authkit_two_factor
// fails while someone must hold MFA but no second factor can be enrolled;
// authkit_issuer_keys fails naming each remote issuer whose JWKS did not
// load (only its tokens are refused); authkit_provider_<name> fails while
// that identity provider is disabled by its configuration or its discovery
// fails (only its sign-ins are refused).
func (a *Client) Probes() []Probe { return a.engine.Probes() }

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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mount.ServeHTTP(w, r.WithContext(a.operationContext(r.Context())))
	})
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
			mux.Handle(route.Pattern(), a.Handler())
		}
	}
	return nil
}
