package authhttp

import (
	"context"

	"github.com/open-rails/authkit/oidckit"
)

// stateConsumer is the optional atomic-consume extension of oidc.StateCache. When
// the configured cache implements it (the bundled memory/redis caches do), the
// browser callbacks consume the OIDC/OAuth2 state in ONE step — closing the
// replay/TOCTOU window that a separate Get-then-Del leaves open. Defined as an
// optional interface so a host's own StateCache implementation stays valid without
// implementing Consume.
type stateConsumer interface {
	Consume(ctx context.Context, state string) (oidckit.StateData, bool, error)
}

// consumeState atomically reads-and-deletes the pending state when the cache
// supports it, falling back to Get+Del otherwise (no worse than before).
func consumeState(ctx context.Context, cache oidckit.StateCache, state string) (oidckit.StateData, bool, error) {
	if c, ok := cache.(stateConsumer); ok {
		return c.Consume(ctx, state)
	}
	sd, ok, err := cache.Get(ctx, state)
	_ = cache.Del(ctx, state)
	return sd, ok, err
}
