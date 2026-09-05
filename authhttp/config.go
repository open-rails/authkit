package authhttp

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/open-rails/authkit/ratelimit"
	"github.com/redis/go-redis/v9"
)

// Config is the HTTP layer's configuration. Engine data lives in
// embedded.Config and engine dependencies in embedded.Deps; this is only what
// the transport itself decides: client-IP posture, rate limiting, languages,
// published documents.
type Config struct {
	// Redis overrides the engine's Redis client for the HTTP layer's OIDC/SIWS
	// state caches and rate limiter. Nil reuses embedded.Deps.Redis (#210), so
	// most hosts never set it.
	Redis *redis.Client

	// RateLimits overlays bucket-specific limits onto DefaultRateLimits (#242).
	RateLimits map[string]ratelimit.Limit
	// Limiter replaces AuthKit's automatic limiter. ADVANCED: normal
	// deployments let AuthKit own the policy (Redis-backed when Redis is wired,
	// in-memory otherwise). RateLimits are not applied to a custom limiter.
	Limiter RateLimiter
	// DisableRateLimiting turns rate limiting off. TESTS ONLY: it removes the
	// brute-force and spam protection.
	DisableRateLimiting bool

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

	// Documents are the published-document providers (normally
	// *documents.Service values) served at the RouteDocuments mount and
	// stamped by the delegated-token mint route (#260/#261). Requires
	// embedded.Config.Documents.Readers.
	Documents []DocumentProvider

	// memoryLimiterSweep overrides how often the in-memory limiter reclaims
	// idle buckets (#305); tests only, the default is one minute.
	memoryLimiterSweep time.Duration
}

// Validate checks the static configuration: parseable proxy CIDRs, one
// rate-limit choice, and a declared client-IP posture.
func (c Config) Validate() error {
	if _, err := parseProxyCIDRs("trusted proxy", c.TrustedProxies); err != nil {
		return err
	}
	if _, err := parseProxyCIDRs("Cloudflare proxy", c.CloudflareProxies); err != nil {
		return err
	}
	if c.Limiter != nil && c.DisableRateLimiting {
		return errors.New("authkit: authhttp.Config.Limiter and DisableRateLimiting are mutually exclusive")
	}
	if !c.DisableRateLimiting && c.Limiter == nil {
		for bucket := range c.RateLimits {
			if strings.TrimSpace(bucket) == "" {
				return errors.New("authkit: authhttp.Config.RateLimits has an empty bucket name")
			}
		}
	}
	if c.ClientIP == nil && !c.DirectPeerIP && len(c.TrustedProxies) == 0 && len(c.CloudflareProxies) == 0 {
		return errors.New("authkit: a client-IP posture is required — set authhttp.Config.TrustedProxies/CloudflareProxies for the proxies in front, DirectPeerIP to assert there are none, or ClientIP; behind an undeclared proxy every client shares one rate-limit bucket")
	}
	for _, p := range c.Documents {
		if p == nil {
			return errors.New("authkit: authhttp.Config.Documents contains a nil provider")
		}
	}
	return nil
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
