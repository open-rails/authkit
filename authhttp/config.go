package authhttp

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strings"

	"github.com/open-rails/authkit/ratelimit"
	"github.com/redis/go-redis/v9"
)

// Config is the HTTP layer's configuration. Engine data lives in
// embedded.Config and engine dependencies in embedded.Deps; this is only what
// the transport itself decides: client-IP posture, rate limiting, languages,
// published documents.
type Config struct {
	// Mount configures the complete HTTP inventory once on the local runtime.
	// It is consumed by Runtime.ConfigureHTTP; framework mounting adds no policy.
	Mount MountOptions

	// DPoPRequestURL returns the externally visible delegation endpoint URL when
	// a proxy rewrites its path. Nil uses embedded.Config.Token.Issuer's origin and the
	// received escaped path. Never derive it from untrusted forwarding headers.
	DPoPRequestURL func(*http.Request) string

	// Rate limiting is an explicit choice; exactly one of Redis, Limiter,
	// PerProcessRateLimits and DisableRateLimiting is required.
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
	// PerProcessRateLimits keeps counters in each process. Correct for one
	// replica only: N replicas allow N times every limit, including password
	// guesses.
	PerProcessRateLimits bool
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
	choices := 0
	for _, set := range []bool{c.Redis != nil, c.Limiter != nil, c.PerProcessRateLimits, c.DisableRateLimiting} {
		if set {
			choices++
		}
	}
	if choices != 1 {
		return errors.New("authkit: choose exactly one rate limiter: authhttp.Config.Redis (shared by replicas), Limiter, PerProcessRateLimits (single replica only) or DisableRateLimiting (tests only)")
	}
	if c.Limiter == nil && !c.DisableRateLimiting {
		if err := ratelimit.ValidateLimits(c.RateLimits); err != nil {
			return err
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
		return "", fmt.Errorf("authkit: invalid authhttp.Config.RedisKeyPrefix %q (want ^[a-z0-9_.:-]{1,64}$)", prefix)
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
