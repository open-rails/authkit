// Package embedded is the public, embedder-facing API of AuthKit.
//
// The full service implementation lives in internal/authcore (driven by the
// authkit/http transport). core re-exports the public data types, config,
// constants, sentinel errors, and helper functions (see aliases.go), and
// exposes a deliberately small Client facade: only the methods an embedding
// application needs to provision, manage, mint, and query. Auth-flow plumbing
// that exists solely to serve the HTTP handlers is intentionally NOT on this
// facade — it stays internal so the v1 contract stays small and stable.
package embedded

import (
	"github.com/jackc/pgx/v5/pgxpool"

	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/verify"
)

// The facade satisfies verify.Enricher so a verify-only embedder that also holds
// a *embedded.Client can attach DB-backed enrichment via verifier.WithService. It is
// also wired in as the verify.RemoteApplicationSource (verifier.fedSource) for
// lazy-load-on-miss, so pin that conformance at compile time too: both are held
// together by the embedded.RemoteApplication = authkit.RemoteApplication alias chain,
// which nothing else guarantees.
var (
	_ verify.Enricher                = (*Client)(nil)
	_ verify.RemoteApplicationSource = (*Client)(nil)
)

// Client is the public AuthKit service facade. It wraps the internal engine
// and exposes the curated embedder API (facade_methods.go). Construct it with
// NewFromConfig (recommended) or NewService.
type Client struct {
	impl *authcore.Service
}

// NewFromConfig builds a Client from host configuration. Postgres is required
// (positional); optional dependencies are functional options.
func New(cfg Config, pg *pgxpool.Pool, extraOpts ...Option) (*Client, error) {
	impl, err := authcore.NewFromConfig(cfg, pg, extraOpts...)
	if err != nil {
		return nil, err
	}
	return &Client{impl: impl}, nil
}

// Wrap adapts an internal engine into the public facade. It is used by the
// authkit/http transport to back svc.Client(); the parameter type lives in
// internal/ and cannot be named (or constructed) outside the module, so this
// does not expose the full engine to external callers.
func Wrap(impl *authcore.Service) *Client { return &Client{impl: impl} }
