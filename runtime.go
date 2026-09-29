package authkit

import (
	"context"
	"net/http"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/verify"
	riverhelpers "github.com/open-rails/helpers/river"
)

// Runtime owns the local engine and its resources. Applications perform all
// business and administrator operations through Client. The engine is a named,
// private field so none of its operation or storage methods escape on Runtime.
type Runtime struct {
	engine      *engine
	verifier    *verify.Verifier
	requireLive func(http.Handler) http.Handler
	http        *httpapi.Service
	mount       *httpapi.Mount
}

// New constructs one local runtime, including Config.HTTP when configured.
func New(cfg Config, deps Deps) (*Runtime, error) {
	engine, err := newEngine(cfg, deps)
	if err != nil {
		return nil, err
	}
	return assemble(engine, cfg.HTTP)
}

// NewWithKeys constructs a runtime with an explicit fixed signing keyset.
func NewWithKeys(cfg Config, keys Keyset, deps Deps) (*Runtime, error) {
	engine, err := newEngineWithKeys(cfg, keys, deps)
	if err != nil {
		return nil, err
	}
	return assemble(engine, cfg.HTTP)
}

func assemble(engine *engine, httpCfg *HTTPConfig) (_ *Runtime, err error) {
	r := &Runtime{engine: engine}
	defer func() {
		if err != nil {
			r.Close()
		}
	}()
	if err := engine.initializeGroups(); err != nil {
		return nil, err
	}
	if r.verifier, err = engine.newVerifier(); err != nil {
		return nil, err
	}
	if r.requireLive, err = verify.RequiredLive(r.verifier); err != nil {
		return nil, err
	}
	if httpCfg != nil {
		if r.http, r.mount, err = newHTTP(engine, r.verifier, *httpCfg); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *Runtime) Client() iam.Client {
	if r == nil {
		return nil
	}
	return r.engine.Client()
}

// Close releases AuthKit-owned resources. Host-owned dependencies stay open.
func (r *Runtime) Close() {
	if r == nil {
		return
	}
	r.http.Close()
	r.engine.Close()
}

func (r *Runtime) Start(ctx context.Context) error      { return r.engine.Start(ctx) }
func (r *Runtime) RiverJobs() riverhelpers.Contribution { return r.engine.RiverJobs() }

// SetEntitlementsProvider resolves the AuthKit/billing construction cycle.
// The provider remains a host-owned dependency, not a Client operation.
func (r *Runtime) SetEntitlementsProvider(provider EntitlementsProvider) {
	r.engine.SetEntitlementsProvider(provider)
}

// CheckSMSHealth probes, without sending, whether the SMS sender can deliver
// and records the verdict that gates phone flows. Register it as a recurring
// dependency probe; every call re-records.
func (r *Runtime) CheckSMSHealth(ctx context.Context) error { return r.engine.CheckSMSHealth(ctx) }
