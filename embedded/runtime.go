package embedded

import (
	"context"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/verify"
	riverhelpers "github.com/open-rails/helpers/river"
)

// Runtime owns the local engine and its resources. Applications perform all
// business and administrator operations through Client. The engine is a named,
// private field so none of its operation or storage methods escape on Runtime.
type Runtime struct{ engine *engine }

// New constructs one local runtime, including Config.HTTP when configured.
func New(cfg Config, deps Deps) (*Runtime, error) {
	engine, err := newEngine(cfg, deps)
	if err != nil {
		return nil, err
	}
	return &Runtime{engine: engine}, nil
}

// NewWithKeys constructs a runtime with an explicit fixed signing keyset.
func NewWithKeys(cfg Config, keys Keyset, deps Deps) (*Runtime, error) {
	engine, err := newEngineWithKeys(cfg, keys, deps)
	if err != nil {
		return nil, err
	}
	if err := engine.initializeGroups(); err != nil {
		engine.Close()
		return nil, err
	}
	if cfg.HTTP != nil {
		if err := engine.ConfigureHTTP(cfg.HTTP); err != nil {
			engine.Close()
			return nil, err
		}
	}
	return &Runtime{engine: engine}, nil
}

func (r *Runtime) Client() authkit.Client {
	if r == nil {
		return nil
	}
	return r.engine.Client()
}

func (r *Runtime) Close() {
	if r != nil {
		r.engine.Close()
	}
}

func (r *Runtime) Start(ctx context.Context) error      { return r.engine.Start(ctx) }
func (r *Runtime) RiverJobs() riverhelpers.Contribution { return r.engine.RiverJobs() }

// ConfigureHTTP is for hosts that must finish provisioning before selecting
// HTTP policy. Prefer Config.HTTP when the policy is known at construction.
func (r *Runtime) ConfigureHTTP(cfg HTTPConfiguration) error { return r.engine.ConfigureHTTP(cfg) }
func (r *Runtime) HTTPRoutes() ([]HTTPRoute, error)          { return r.engine.HTTPRoutes() }
func (r *Runtime) Verifier() *verify.Verifier                { return r.engine.Verifier() }

// SetEntitlementsProvider resolves the AuthKit/billing construction cycle.
// The provider remains a host-owned dependency, not a Client operation.
func (r *Runtime) SetEntitlementsProvider(provider EntitlementsProvider) {
	r.engine.SetEntitlementsProvider(provider)
}
