// Package core is the public, embedder-facing API of AuthKit.
//
// The full service implementation lives in internal/authcore (driven by the
// authkit/http transport). core re-exports the public data types, config,
// constants, sentinel errors, and helper functions (see aliases.go), and
// exposes a deliberately small Service facade: only the methods an embedding
// application needs to provision, manage, mint, and query. Auth-flow plumbing
// that exists solely to serve the HTTP handlers is intentionally NOT on this
// facade — it stays internal so the v1 contract stays small and stable.
package core

import (
	"github.com/jackc/pgx/v5/pgxpool"

	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/verify"
)

// The facade satisfies verify.Enricher so a verify-only embedder that also holds
// a *core.Service can attach DB-backed enrichment via verifier.WithService.
var _ verify.Enricher = (*Service)(nil)

// Service is the public AuthKit service facade. It wraps the internal engine
// and exposes the curated embedder API (facade_methods.go). Construct it with
// NewFromConfig (recommended) or NewService.
type Service struct {
	impl *authcore.Service
}

// NewFromConfig builds a Service from host configuration. Postgres is required
// (positional); optional dependencies are functional options.
func NewFromConfig(cfg Config, pg *pgxpool.Pool, extraOpts ...Option) (*Service, error) {
	impl, err := authcore.NewFromConfig(cfg, pg, extraOpts...)
	if err != nil {
		return nil, err
	}
	return &Service{impl: impl}, nil
}

// NewService builds a Service from already-resolved Options and Keyset.
func NewService(opts Options, keys Keyset, coreOpts ...Option) *Service {
	return &Service{impl: authcore.NewService(opts, keys, coreOpts...)}
}

// Wrap adapts an internal engine into the public facade. It is used by the
// authkit/http transport to back svc.Core(); the parameter type lives in
// internal/ and cannot be named (or constructed) outside the module, so this
// does not expose the full engine to external callers.
func Wrap(impl *authcore.Service) *Service { return &Service{impl: impl} }
