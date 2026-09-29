package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strings"

	"github.com/open-rails/authkit/internal/ratelimit"
	"github.com/redis/go-redis/v9"
)

// Config is the HTTP layer's configuration. Engine data lives in
// authkit.Config and engine dependencies in authkit.Deps; this is only what
// the transport itself decides: client-IP posture, rate limiting, languages.
type Config struct {
	// Mount configures the route inventory NewMount builds; framework
	// adapters add no policy.
	Mount MountOptions

	// DPoPRequestURL returns the externally visible delegation endpoint URL when
	// a proxy rewrites its path. Nil uses authkit.Config.Token.Issuer's origin and the
	// received escaped path. Never derive it from untrusted forwarding headers.
	DPoPRequestURL func(*http.Request) string

	// Rate limiting defaults to in-memory, per-process counters. Redis shares
	// them across replicas; Limiter replaces the limiter. At most one of the
	// two may be set.
	//
	// Redis shares rate-limit counters across replicas. It holds no other
	// AuthKit state.
	Redis redis.UniversalClient
	// RedisKeyPrefix namespaces the rate-limit keys so several deployments can
	// share one Redis (#307). Empty derives "authkit:<schema>:"; a trailing ':'
	// is added when missing. Must match ^[a-z0-9_.:-]{1,64}$.
	RedisKeyPrefix string

	// RateLimits overlays bucket-specific limits onto DefaultRateLimits (#242).
	RateLimits map[string]ratelimit.Limit
	// Limiter replaces AuthKit's limiter. ADVANCED: RateLimits are not applied
	// to a custom limiter.
	Limiter RateLimiter

	// Client-IP posture (ak#299). Exactly what sits in front of AuthKit must be
	// declared — behind an undeclared proxy every client shares the proxy's one
	// per-IP rate-limit bucket. One of the four is required.
	//
	// TrustedProxies are the CIDRs of reverse proxies / load balancers whose
	// X-Forwarded-For is honoured (walked right-to-left past our own hops).
	// CF-Connecting-IP is never trusted from these peers.
	TrustedProxies []string
	// CloudflareProxies are Cloudflare's published egress ranges: X-Forwarded-For
	// like a trusted proxy plus CF-Connecting-IP when that header is absent.
	// Set it ONLY where Cloudflare fronts the origin, and lock the origin down
	// to Cloudflare ingress.
	CloudflareProxies []string
	// DirectPeerIP asserts nothing sits in front: RemoteAddr IS the end client.
	DirectPeerIP bool
	// ClientIP is a bespoke extraction strategy. ADVANCED: it replaces the
	// proxy handling above entirely.
	ClientIP ClientIPFunc

	// Languages declares the supported UI languages; the zero value is
	// English-only.
	Languages LanguageConfig
}

// Validate checks the static configuration: parseable proxy CIDRs, at most
// one rate-limit choice, and a declared client-IP posture.
func (c Config) Validate() error {
	if _, err := parseProxyCIDRs("trusted proxy", c.TrustedProxies); err != nil {
		return err
	}
	if _, err := parseProxyCIDRs("Cloudflare proxy", c.CloudflareProxies); err != nil {
		return err
	}
	if c.Redis != nil && c.Limiter != nil {
		return errors.New("authkit: conflicting rate limiting: set at most one of HTTPConfig.Redis and Limiter")
	}
	if c.Limiter == nil {
		if err := ratelimit.ValidateLimits(c.RateLimits); err != nil {
			return err
		}
		known := DefaultRateLimits()
		for bucket := range c.RateLimits {
			if _, ok := known[bucket]; !ok {
				return fmt.Errorf("authkit: RateLimits names unknown bucket %q", bucket)
			}
		}
	}
	if c.ClientIP == nil && !c.DirectPeerIP && len(c.TrustedProxies) == 0 && len(c.CloudflareProxies) == 0 {
		return errors.New("authkit: a client-IP posture is required — set HTTPConfig.TrustedProxies/CloudflareProxies for the proxies in front, DirectPeerIP to assert there are none, or ClientIP; behind an undeclared proxy every client shares one rate-limit bucket")
	}
	return nil
}

var redisKeyPrefixRE = regexp.MustCompile(`^[a-z0-9_.:-]{1,64}$`)

func redisKeyPrefix(prefix, schema string) (string, error) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		prefix = "authkit:" + schema + ":"
	}
	if !strings.HasSuffix(prefix, ":") {
		prefix += ":"
	}
	if !redisKeyPrefixRE.MatchString(prefix) {
		return "", fmt.Errorf("authkit: invalid HTTPConfig.RedisKeyPrefix %q (want ^[a-z0-9_.:-]{1,64}$)", prefix)
	}
	return prefix, nil
}

func parseProxyCIDRs(kind string, cidrs []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return nil, fmt.Errorf("authkit: invalid %s CIDR %q: %w", kind, c, err)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}
