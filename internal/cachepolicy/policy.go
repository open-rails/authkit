// Package cachepolicy is AuthKit's read-cache policy in one place: each
// in-process cache and its bounds. Every other read is live, so revoking a
// session, grant, API key, OAuth client or remote application takes effect
// on the next request.
package cachepolicy

import (
	"time"

	"github.com/open-rails/helpers/cache"
)

var (
	// IssuerKeys is a trusted issuer's JWKS. A key it stops publishing stops
	// verifying within RefreshAfter; an unreachable issuer's keys fail closed
	// past MaxStale, so blocking the fetch cannot keep a revoked key valid.
	IssuerKeys = cache.Options{Name: "authkit_issuer_keys", RefreshAfter: 10 * time.Minute, MaxStale: 4 * time.Hour,
		LoadTimeout: 3 * time.Second, FailureBackoff: 5 * time.Second}

	// OIDCDiscovery is a login provider's metadata and the key set built
	// with it: a key the IdP revokes stops verifying within RefreshAfter.
	OIDCDiscovery = cache.Options{Name: "authkit_oidc_discovery", RefreshAfter: time.Hour, MaxStale: 4 * time.Hour,
		LoadTimeout: 5 * time.Second, FailureBackoff: 5 * time.Second}
)

// IssuerKeysRefetchMin spaces the refetches an unknown kid or a failed
// signature forces, so forged tokens cannot hammer an issuer.
const IssuerKeysRefetchMin = 30 * time.Second

// New is cache.New for a policy above; an invalid one is a programming error.
func New[K comparable, V any](o cache.Options, load cache.Load[K, V]) *cache.Cache[K, V] {
	c, err := cache.New(o, load)
	if err != nil {
		panic("authkit: " + err.Error())
	}
	return c
}

// Now is o's clock.
func Now(o cache.Options) time.Time {
	if o.Clock != nil {
		return o.Clock.Now()
	}
	return time.Now()
}
