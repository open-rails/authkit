package authhttp

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/open-rails/authkit/embedded"
	memorylimiter "github.com/open-rails/authkit/ratelimit/memory"
	redislimiter "github.com/open-rails/authkit/ratelimit/redis"
	memorystore "github.com/open-rails/authkit/storage/memory"
	"github.com/redis/go-redis/v9"
)

// Server is the exported, recommended name for the net/http mounting wrapper
// embedders construct with NewServer (it IS an HTTP server). Service is the
// original struct name, kept as an alias; both refer to the same type. The #109
// collision — a second public type also named Service — is resolved by #138: the
// embedder-facing facade is now embedded.Client, reached via Server.Client().
type Server = Service

// Option configures a Server at construction. Options are applied INSIDE
// NewServer, before the core service is built, so a half-built Server is never
// observable. This is the ONLY way to wire optional dependencies — the chainable
// WithX builder methods were removed in #108.
type Option func(*Server)

// NewServer constructs the auth Server over a client the host already built —
// client-first construction (#142). The host wires the engine and its
// dependencies on embedded.New; NewServer is the HTTP adapter over it and takes
// only HTTP-layer options. Postgres is REQUIRED: the durable user/role and
// permission-group store has no in-memory fallback (#106), so the client must be
// Postgres-backed; pure token verification with no storage uses
// authhttp.NewVerifier / authkit/verify instead.
//
//	client, err := embedded.New(cfg, pg, embedded.WithEmailSender(mailer))
//	srv, err := authhttp.NewServer(client,
//	    authhttp.WithRedis(rdb), // OIDC/SIWS state caches
//	)
func NewServer(client *embedded.Client, opts ...Option) (*Server, error) {
	if client == nil || client.Postgres() == nil {
		return nil, errors.New("authkit: authhttp.NewServer requires a Postgres-backed *embedded.Client (Postgres is mandatory)")
	}
	coreSvc := embedded.Unwrap(client)
	cfg := coreSvc.Config()

	// HTTP-level defaults set BEFORE options so an option can override them.
	s := &Server{
		clientIP: DefaultClientIP(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	s.svc = coreSvc

	// AuthKit owns the rate-limit policy: auto-create the limiter unless the host
	// explicitly set or disabled one (the advanced/test-only WithRateLimiter /
	// WithoutRateLimiter seams). Redis-backed when a Redis client is supplied via
	// authhttp.WithRedis, so limits are shared across instances; in-memory otherwise.
	if !s.rlExplicit {
		if s.rd != nil {
			s.rl = redislimiter.New(s.rd, DefaultRateLimits())
		} else {
			s.rl = memorylimiter.New(DefaultRateLimits())
		}
	}

	o := coreSvc.Options()
	ver := NewVerifier(
		WithSkew(5*time.Second),
		WithAPIKeyPrefix(o.APIKeyPrefix),
		WithSSRFGuard(),
	)
	_ = ver.AddIssuer(o.Issuer, o.ExpectedAudiences, IssuerOptions{
		RawKeys: coreSvc.PublicKeysByKID(),
		IsLocal: true,
	})
	ver.WithService(coreSvc)
	s.verifier = ver

	authProvidersByName, err := buildAuthProvidersMap(cfg.Identity.Providers)
	if err != nil {
		return nil, err
	}
	s.authProvidersByName = authProvidersByName
	s.memStateCache = memorystore.NewStateCache(15 * time.Minute)

	if err := s.validate(cfg); err != nil {
		return nil, err
	}
	return s, nil
}

// validate enforces the CONDITIONAL dependency requirements for the configured
// feature set (pg is already guaranteed by the signature).
func (s *Server) validate(cfg embedded.Config) error {
	if s.trustedProxyErr != nil {
		return s.trustedProxyErr
	}
	env := strings.ToLower(strings.TrimSpace(cfg.Environment))
	if env == "prod" || env == "production" {
		if s.rd == nil {
			return fmt.Errorf("authkit: production requires a Redis-compatible ephemeral store — pass authhttp.WithRedis(...); a memory store is dev-only")
		}
	}
	return nil
}

// --- Functional options (#108). These are HTTP-LAYER options only; engine
// dependencies (email/SMS senders, entitlements, ephemeral store, auth logger,
// API-key authorizer, Solana resolver) are wired on embedded.New, since the host
// builds the client before constructing the server (client-first, #142). ---

// WithRedis supplies the Redis client for the HTTP layer's OIDC and SIWS state
// caches (and satisfies the production durable-store requirement). The engine's
// ephemeral store takes the same *redis.Client separately via embedded.WithRedis.
func WithRedis(rd *redis.Client) Option {
	return func(s *Server) { s.rd = rd }
}

// WithRateLimiter overrides AuthKit's automatic rate limiter. ADVANCED/TEST ONLY:
// normal deployments let AuthKit own the policy (Redis-backed when WithRedis is
// supplied, in-memory otherwise) and must not inject a custom limiter.
func WithRateLimiter(rl RateLimiter) Option {
	return func(s *Server) { s.rl = rl; s.rlExplicit = true }
}

// WithoutRateLimiter disables rate limiting. ADVANCED/TEST ONLY: never use in
// production — it removes brute-force and spam protection.
func WithoutRateLimiter() Option {
	return func(s *Server) { s.rl = nil; s.rlExplicit = true }
}

// WithTrustedProxies is the normal knob for deployments behind a reverse proxy or
// CDN: AuthKit derives the client IP (for rate limiting + auditing) from forwarded
// headers (CF-Connecting-IP / X-Forwarded-For) ONLY when the immediate peer is in
// one of the given trusted-proxy CIDRs; otherwise it uses the direct peer
// (RemoteAddr). With no trusted proxies the safe RemoteAddr default applies. An
// invalid CIDR fails NewServer rather than silently mis-trusting a proxy.
func WithTrustedProxies(cidrs ...string) Option {
	return func(s *Server) {
		prefixes := make([]netip.Prefix, 0, len(cidrs))
		for _, c := range cidrs {
			p, err := netip.ParsePrefix(strings.TrimSpace(c))
			if err != nil {
				s.trustedProxyErr = fmt.Errorf("authkit: invalid trusted proxy CIDR %q: %w", c, err)
				return
			}
			prefixes = append(prefixes, p)
		}
		s.clientIP = ClientIPFromForwardedHeaders(prefixes)
	}
}

// WithClientIPFunc sets the client-IP extraction strategy. ADVANCED/TEST ONLY:
// normal deployments use WithTrustedProxies (proxy CIDRs) or the RemoteAddr
// default; inject a raw ClientIPFunc only for bespoke strategies.
func WithClientIPFunc(fn ClientIPFunc) Option {
	return func(s *Server) {
		if fn == nil {
			fn = DefaultClientIP()
		}
		s.clientIP = fn
	}
}

// WithLanguageConfig sets the i18n language configuration.
func WithLanguageConfig(cfg LanguageConfig) Option {
	return func(s *Server) { s.langCfg = &cfg }
}
