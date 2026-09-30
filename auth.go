package authkit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/builtwith"
	"github.com/open-rails/authkit/internal/engine"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/ops"
	"github.com/open-rails/authkit/verify"
	riverhelpers "github.com/open-rails/helpers/river"
)

// Client is AuthKit embedded in a host: the engine and, when Config.HTTP is
// set, its HTTP surface. Build it with New, then Start it. Operations are
// methods, grouped by domain in the auth_*.go files. It is the authority
// verify's middleware takes: verify.Required(client),
// verify.RequirePermission(client, perm).
//
// Start, Close, RiverJobs, SMSAvailable, SMSHealth, TwoFactorMethods,
// Handler, Routes, Mount and the request verification methods
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
}

func init() {
	builtwith.Of = func(client any) (Config, Deps, bool) {
		a, ok := client.(*Client)
		if !ok || a == nil {
			return Config{}, Deps{}, false
		}
		return a.cfg, a.deps, true
	}
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
			a.Close()
		}
	}()
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

// Start starts AuthKit's background work: River (account lifecycle, events,
// auth-state cleanup) and the Deps.SMSHealth checks. Call it once, before
// serving.
func (a *Client) Start(ctx context.Context) error { return a.engine.Start(ctx) }

// RiverJobs contributes AuthKit's jobs to a host-owned River fleet
// (Config.River.HostOwned).
func (a *Client) RiverJobs() riverhelpers.Contribution { return a.engine.RiverJobs() }

// Close releases AuthKit-owned resources. Host-owned dependencies stay open.
func (a *Client) Close() {
	if a == nil {
		return
	}
	a.http.Close()
	a.engine.Close()
}

// SMSAvailable reports whether phone flows are offered: Deps.SMS is set and
// the latest Deps.SMSHealth check, if any, passed.
func (a *Client) SMSAvailable() bool { return a.engine.SMSAvailable() }

// SMSHealth is the latest Deps.SMSHealth verdict and when it ran (Start runs
// it every Config.SMSHealthInterval); a zero time means no check has run.
func (a *Client) SMSHealth() (checkedAt time.Time, err error) { return a.engine.SMSHealth() }

// TwoFactorMethods are the second factors a user can enroll now, as GET
// /capabilities lists them: enabled by Config.TwoFactor, with their
// dependency present (Deps.Email, Deps.SMS while healthy, the TOTP key).
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
