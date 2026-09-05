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
	memorystore "github.com/open-rails/authkit/internal/storage/memory"
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
// New.
type Client struct {
	impl *Service
}

// New builds a Client from host configuration and runtime dependencies.
// Deps.Postgres is required; with neither Deps.Redis nor Deps.EphemeralStore
// the ephemeral store is the per-process memory store, which needs the explicit
// Config.Ephemeral.AllowMemory opt-in (#305).
func New(cfg Config, deps Deps) (*Client, error) {
	if deps.Redis == nil && deps.EphemeralStore == nil {
		deps.EphemeralStore = memorystore.NewKV()
	}
	impl, err := NewFromConfig(cfg, deps)
	if err != nil {
		return nil, err
	}
	return &Client{impl: impl}, nil
}

// Unwrap returns the internal engine a Client wraps, for the authkit/http
// transport's client-first NewServer (it builds route handlers over the engine).
// The return type lives in internal/ and is unnameable outside the module.
func Unwrap(c *Client) *Service { return c.impl }
