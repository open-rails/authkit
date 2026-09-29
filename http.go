package authkit

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/ratelimit"
	"github.com/open-rails/authkit/verify"
)

// HTTPConfig configures AuthKit's HTTP surface: one handler serving the JSON
// API, browser OIDC, JWKS and published documents. The engine's own policy
// lives in Config; this is only what the transport decides.
type HTTPConfig struct {
	// Groups selects the mounted route groups. Nil mounts the default API
	// surface plus browser OIDC; non-nil mounts exactly the named groups.
	Groups []iam.RouteGroup
	// APIPrefix anchors the JSON API. "" means "/api/v1"; "/" mounts it at
	// root. JWKS, browser OIDC and documents keep their root anchors.
	APIPrefix string
	// Exclude drops routes the host serves itself, named as Patterns reports
	// them ("GET /.well-known/jwks.json"). An entry matching no route is an
	// error.
	Exclude []string
	// Wrap decorates every API and browser-OIDC handler at mount time.
	Wrap func(iam.Route, http.Handler) http.Handler
	// RefreshCookie delivers the rotating refresh token as an HttpOnly cookie
	// (iam.RefreshCookieName) instead of a JSON body field. Browser mounts
	// only: the SPA and this handler must share an origin.
	RefreshCookie bool
	// DPoPRequestURL returns the externally visible delegation endpoint URL
	// when a proxy rewrites its path. Nil uses the issuer's origin and the
	// received path. Never derive it from untrusted forwarding headers.
	DPoPRequestURL func(*http.Request) string

	// Rate limiting is in-memory and per-process by default: each replica
	// counts separately. Set Redis when running more than one replica. At most
	// one of Redis, Limiter and DisableRateLimiting may be set.
	//
	// Redis shares rate-limit counters across replicas; it holds no other
	// AuthKit state.
	Redis redis.UniversalClient
	// RedisKeyPrefix namespaces the rate-limit keys so deployments can share
	// one Redis. Empty derives "authkit:<schema>:".
	RedisKeyPrefix string
	// RateLimits overlays bucket limits onto DefaultRateLimits; unknown
	// buckets are refused.
	RateLimits map[string]RateLimit
	// Limiter replaces AuthKit's limiter; RateLimits do not apply to it.
	Limiter RateLimiter
	// DisableRateLimiting turns rate limiting off. Tests only.
	DisableRateLimiting bool

	// Client-IP posture: exactly what sits in front of AuthKit must be
	// declared, or every client shares a proxy's one per-IP bucket.
	//
	// TrustedProxies are reverse proxies whose X-Forwarded-For is honoured.
	TrustedProxies []string
	// CloudflareProxies are Cloudflare's egress ranges: X-Forwarded-For plus
	// CF-Connecting-IP. Set only where Cloudflare fronts a locked-down origin.
	CloudflareProxies []string
	// DirectPeerIP asserts nothing sits in front: RemoteAddr is the client.
	DirectPeerIP bool
	// ClientIP replaces the proxy handling above entirely.
	ClientIP func(*http.Request) string

	// Languages declares the supported UI languages; the zero value is
	// English-only.
	Languages LanguageConfig
	// Documents are the published-document providers (normally
	// *documents.Service) served at iam.DocumentsPath and stamped into
	// delegated tokens. Requires Config.Documents.Readers.
	Documents []documents.Provider
}

// RateLimit allows at most Limit requests per Window in one bucket, with an
// optional Cooldown between accepted requests.
type RateLimit struct {
	Limit    int
	Window   time.Duration
	Cooldown time.Duration
}

// RateLimiter is a host-supplied limiter keyed by bucket name and client key.
type RateLimiter interface {
	AllowNamed(bucket, key string) (bool, error)
}

// LanguageConfig declares the UI languages the HTTP surface negotiates.
type LanguageConfig struct {
	Supported []string
	Default   string
}

// DefaultRateLimits returns AuthKit's built-in per-endpoint limits, keyed by
// bucket name ("default" applies to unlisted buckets).
func DefaultRateLimits() map[string]RateLimit {
	out := map[string]RateLimit{}
	for bucket, l := range httpapi.DefaultRateLimits() {
		out[bucket] = RateLimit{Limit: l.Limit, Window: l.Window, Cooldown: l.Cooldown}
	}
	return out
}

func (c HTTPConfig) internal() httpapi.Config {
	out := httpapi.Config{
		Mount: httpapi.MountOptions{
			Groups:        append([]iam.RouteGroup(nil), c.Groups...),
			APIPrefix:     c.APIPrefix,
			Exclude:       append([]string(nil), c.Exclude...),
			Wrap:          c.Wrap,
			RefreshCookie: c.RefreshCookie,
		},
		DPoPRequestURL:      c.DPoPRequestURL,
		Redis:               c.Redis,
		RedisKeyPrefix:      c.RedisKeyPrefix,
		DisableRateLimiting: c.DisableRateLimiting,
		TrustedProxies:      append([]string(nil), c.TrustedProxies...),
		CloudflareProxies:   append([]string(nil), c.CloudflareProxies...),
		DirectPeerIP:        c.DirectPeerIP,
		ClientIP:            c.ClientIP,
		Languages:           httpapi.LanguageConfig{Supported: append([]string(nil), c.Languages.Supported...), Default: c.Languages.Default},
		Documents:           append([]documents.Provider(nil), c.Documents...),
	}
	if c.Limiter != nil {
		out.Limiter = c.Limiter
	}
	if c.RateLimits != nil {
		out.RateLimits = make(map[string]ratelimit.Limit, len(c.RateLimits))
		for bucket, l := range c.RateLimits {
			out.RateLimits[bucket] = ratelimit.Limit{Limit: l.Limit, Window: l.Window, Cooldown: l.Cooldown}
		}
	}
	return out
}

// newVerifier builds the engine's request verifier: its own issuer's keys,
// the engine as enricher, liveness source and permission checker.
func (s *engine) newVerifier() (*verify.Verifier, error) {
	cfg := s.cfg
	opts := []verify.VerifierOption{
		verify.WithSkew(5 * time.Second),
		verify.WithAPIKeyPrefix(cfg.APIKeys.Prefix),
		verify.WithRemoteApplicationAudiences(cfg.Token.ExpectedAudiences...),
		// #240: required 2FA challenges every un-enrolled user on their next
		// request, not just at mint time.
		verify.WithRequireMFAEnrollment(cfg.TwoFactor.Mode == iam.TwoFactorRequired),
	}
	// Applications.AllowPrivateNetworkJWKS is the local-federation carve-out
	// (#257) from the SSRF guard on JWKS fetches.
	if !cfg.Applications.AllowPrivateNetworkJWKS {
		opts = append(opts, verify.WithSSRFGuard())
	}
	v := verify.NewVerifier(opts...)
	if cfg.Token.Issuer != "" {
		if err := v.AddIssuer(cfg.Token.Issuer, cfg.Token.ExpectedAudiences, verify.IssuerOptions{
			PublicKeys: s.PublicKeysByKID,
			IsLocal:    true,
		}); err != nil {
			return nil, err
		}
	}
	v.WithService(s).WithLiveness(s).WithPermissionChecker(s, cfg.Token.Issuer)
	return v, nil
}

// newHTTP builds the HTTP layer and its one mounted handler.
func newHTTP(s *engine, v *verify.Verifier, cfg HTTPConfig) (*httpapi.Service, *httpapi.Mount, error) {
	if s.pg == nil {
		return nil, nil, errors.New("authkit: HTTP requires Deps.Postgres")
	}
	internal := cfg.internal()
	svc, err := httpapi.New(s, v, internal)
	if err != nil {
		return nil, nil, err
	}
	mount, err := httpapi.NewMount(svc, internal.Mount)
	if err != nil {
		svc.Close()
		return nil, nil, err
	}
	return svc, mount, nil
}

// Handler serves AuthKit's whole HTTP surface; nil when Config.HTTP is nil.
// Mount it at the host root: it owns its anchored paths.
func (r *Runtime) Handler() http.Handler {
	if r.mount == nil {
		return nil
	}
	return r.mount
}

// Routes returns the mounted route catalog, with a HEAD entry per GET route.
func (r *Runtime) Routes() []iam.Route { return r.mount.Routes() }

// Patterns returns the mounted routes as net/http ServeMux patterns
// ("GET /api/v1/me"), sorted. A GET pattern also serves HEAD.
func (r *Runtime) Patterns() []string {
	var out []string
	for _, route := range r.mount.Routes() {
		if route.Method == http.MethodHead {
			continue
		}
		out = append(out, route.Method+" "+route.Path)
	}
	sort.Strings(out)
	return out
}

// Mount registers every pattern on mux, all served by Handler.
func (r *Runtime) Mount(mux *http.ServeMux) (err error) {
	if r.mount == nil {
		return errors.New("authkit: HTTP is not configured; set Config.HTTP")
	}
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("authkit: mount: %v", p)
		}
	}()
	for _, pattern := range r.Patterns() {
		mux.Handle(pattern, r.mount)
	}
	return nil
}

// Verifier verifies requests and tokens against this deployment. It exists
// from New on, with or without an HTTP surface.
func (r *Runtime) Verifier() *verify.Verifier { return r.verifier }

// Require rejects requests without a valid credential. Ordinary
// verification is stateless; see RequireLive.
func (r *Runtime) Require(next http.Handler) http.Handler { return verify.Required(r.verifier)(next) }

// Optional verifies a credential when one is presented.
func (r *Runtime) Optional(next http.Handler) http.Handler { return verify.Optional(r.verifier)(next) }

// RequireLive is Require plus a live account check for sensitive operations.
func (r *Runtime) RequireLive(next http.Handler) http.Handler { return r.requireLive(next) }
