package authhttp

import (
	"context"
	"errors"
	"fmt"
	"github.com/open-rails/authkit/verify"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/embedded"
	memorylimiter "github.com/open-rails/authkit/internal/ratelimit/memory"
	redislimiter "github.com/open-rails/authkit/internal/ratelimit/redis"
	memorystore "github.com/open-rails/authkit/internal/storage/memory"
	"github.com/open-rails/authkit/ratelimit"
	"github.com/redis/go-redis/v9"
)

// Option configures a Service at construction. Options are applied INSIDE
// NewServer, before the core service is built, so a half-built Service is never
// observable. This is the ONLY way to wire optional dependencies — the chainable
// WithX builder methods were removed in #108. (#206 collapsed the former `Server`
// alias into the single canonical `Service` type; construct with NewServer.)
type Option func(*Service)

// NewServer constructs the auth Server over a client the host already built —
// client-first construction (#142). The host wires the engine and its
// dependencies on embedded.New; NewServer is the HTTP adapter over it and takes
// only HTTP-layer options. Postgres is REQUIRED: the durable user/role and
// permission-group store has no in-memory fallback (#106), so the client must be
// Postgres-backed; pure token verification with no storage uses
// verify.NewVerifier (authkit/verify) instead.
//
// Construction fails (returns an error, never panics — #212) when the
// configuration cannot be served: in particular, if Registration.Verification is
// "required" but the engine has no email or SMS sender wired (embedded.WithEmailSender
// / embedded.WithSMSSender), NewServer returns an error rather than panicking later
// at handler mount.
//
// Redis is taken ONCE (#210): NewServer reuses the engine's ephemeral Redis client
// (embedded.WithRedis) for the HTTP layer's OIDC/SIWS state caches and rate limiter,
// so a host that wired Redis on the engine need not also pass authhttp.WithRedis.
// authhttp.WithRedis remains available as an explicit override, not a requirement.
//
//	client, err := embedded.New(cfg, pg,
//	    embedded.WithEmailSender(mailer), // required when Verification == "required"
//	    embedded.WithRedis(rdb),          // engine ephemeral store; reused by the HTTP layer
//	)
//	srv, err := authhttp.NewServer(client)
func NewServer(client *embedded.Client, opts ...Option) (*Service, error) {
	if client == nil || client.Postgres() == nil {
		return nil, errors.New("authkit: authhttp.NewServer requires a Postgres-backed *embedded.Client (Postgres is mandatory)")
	}
	if err := probeMigrations(client); err != nil {
		return nil, err
	}
	coreSvc := embedded.Unwrap(client)
	cfg := coreSvc.Config()

	// HTTP-level defaults set BEFORE options so an option can override them.
	s := &Service{
		clientIP: DefaultClientIP(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	s.svc = coreSvc
	if len(s.engineOpts) > 0 && !s.engineOptsAllowed {
		return nil, errors.New("authkit: authhttp.WithEngine is only valid with authhttp.New (one-step); with NewServer the engine is already built — pass engine options to embedded.New instead")
	}

	// #210: take Redis ONCE. When the host wired Redis on the engine
	// (embedded.WithRedis) but did NOT pass authhttp.WithRedis, adopt the engine's
	// *redis.Client for the HTTP layer's OIDC/SIWS caches and rate limiter — one
	// Redis instance, single source of truth, no split-brain ephemeral state. An
	// explicit authhttp.WithRedis (applied above) still overrides.
	if s.rd == nil {
		s.rd = coreSvc.EphemeralRedisClient()
	}

	// AuthKit owns the rate-limit policy: auto-create the limiter unless the host
	// explicitly set or disabled one (the advanced/test-only WithRateLimiter /
	// WithoutRateLimiter seams). Redis-backed when a Redis client is supplied via
	// authhttp.WithRedis, so limits are shared across instances; in-memory otherwise.
	if !s.rlExplicit {
		limits := DefaultRateLimits()
		for bucket, lim := range s.rlOverrides {
			limits[bucket] = lim
		}
		if s.rd != nil {
			s.rl = redislimiter.New(s.rd, limits)
		} else {
			s.rl = memorylimiter.New(limits)
		}
	}

	ver := verify.NewVerifier(
		verify.WithSkew(5*time.Second),
		verify.WithAPIKeyPrefix(cfg.APIKeys.Prefix),
		verify.WithSSRFGuard(),
		// #240: wire the documented per-request forced-2FA-enrollment gate from
		// the host's TwoFactor policy. Required mode challenges every existing
		// un-enrolled user on their next request, not just at mint time.
		verify.WithRequireMFAEnrollment(cfg.TwoFactor.Mode == embedded.TwoFactorRequired),
	)
	_ = ver.AddIssuer(cfg.Token.Issuer, cfg.Token.ExpectedAudiences, verify.IssuerOptions{
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
	s.memSIWSCache = memorystore.NewSIWSCache(15 * time.Minute)

	// #243: derive the 2FA-enrollment allowlist from the route registry (single
	// source of truth — RouteSpec.MFAEnrollmentExempt) instead of a hand-
	// maintained suffix list, so a renamed/added enroll route can't silently
	// drift from the gate. Must run after every field APIRoutes reads is set.
	ver.SetMFAEnrollmentExemptPaths(mfaEnrollmentExemptPaths(s.APIRoutes()))

	if err := s.validate(cfg); err != nil {
		return nil, err
	}
	return s, nil
}

// probeMigrations fails fast at construction when AuthKit's migrations were
// never run — a definitive "users table missing" beats a cryptic mid-request
// `relation "profiles.users" does not exist`. Fail-open on probe errors
// (connectivity, permissions): those surface elsewhere; only a definitive
// "table missing" fails construction.
func probeMigrations(client *embedded.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var exists bool
	err := client.Postgres().QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = $1 AND table_name = 'users')`,
		client.Schema(),
	).Scan(&exists)
	if err != nil || exists {
		return nil
	}
	return fmt.Errorf("authkit: schema %q has no users table — run AuthKit's migrations before constructing the server (authkitmigrate.New(pool, ...).Migrate(ctx))", client.Schema())
}

// validate enforces the CONDITIONAL dependency requirements for the configured
// feature set (pg is already guaranteed by the signature).
func (s *Service) validate(cfg embedded.Config) error {
	if s.trustedProxyErr != nil {
		return s.trustedProxyErr
	}
	// #212: the registration-verification policy must be satisfiable by a
	// configured delivery sender at CONSTRUCTION time. Fail here with an error
	// instead of panicking later when handlers are mounted (APIHandler).
	if err := s.svc.ValidateVerificationConfiguration(); err != nil {
		return err
	}
	// #231: THE single dev/prod classifier — anything not explicitly dev-ish
	// (incl. staging and unknown values) is prod-like and requires the durable
	// ephemeral store. This was the last inline env comparison in library code.
	if !embedded.IsDevEnvironment(cfg.Environment) {
		if s.rd == nil {
			return fmt.Errorf("authkit: Environment %q is production-like and requires a Redis-compatible ephemeral store — pass authhttp.WithRedis(...); a memory store is dev-only", cfg.Environment)
		}
	}
	return nil
}

// --- Functional options (#108). These are HTTP-LAYER options only; engine
// dependencies (email/SMS senders, entitlements, ephemeral store,
// API-key authorizer, Solana resolver) are wired on embedded.New, since the host
// builds the client before constructing the server (client-first, #142). ---

// WithEngine passes embedded-engine options (embedded.WithEmailSender,
// WithSMSSender, WithEntitlements, WithRedis, …) through the
// one-step authhttp.New (#211). It is ONLY valid with New — NewServer returns a
// construction error if it sees engine options, because in the two-step path the
// host already built the engine and these would be silently ignored.
func WithEngine(opts ...embedded.Option) Option {
	return func(s *Service) { s.engineOpts = append(s.engineOpts, opts...) }
}

// allowEngineOpts marks a Service as constructed via New, where WithEngine is legal.
func allowEngineOpts() Option {
	return func(s *Service) { s.engineOptsAllowed = true }
}

// New builds BOTH layers in one call (#211): the embedded engine and the HTTP
// transport over it, collapsing the Config→embedded.New→NewServer glue every
// host copy-pastes. Engine dependencies ride in via WithEngine; all other
// options are the usual authhttp set. The *embedded.Client is returned too —
// it IS the host's authkit.Client. The two-step path (embedded.New + NewServer)
// remains for hosts that need to hold or decorate the engine separately.
func New(cfg embedded.Config, pg *pgxpool.Pool, opts ...Option) (*Service, *embedded.Client, error) {
	probe := &Service{}
	for _, opt := range opts {
		if opt != nil {
			opt(probe)
		}
	}
	client, err := embedded.New(cfg, pg, probe.engineOpts...)
	if err != nil {
		return nil, nil, err
	}
	svc, err := NewServer(client, append([]Option{allowEngineOpts()}, opts...)...)
	if err != nil {
		return nil, nil, err
	}
	return svc, client, nil
}

// WithRedis supplies the Redis client for the HTTP layer's OIDC and SIWS state
// caches (and satisfies the production durable-store requirement). It is an
// OVERRIDE, not a requirement: when the engine already has Redis wired via
// embedded.WithRedis, NewServer reuses that client for the HTTP layer by default
// (#210), so most hosts pass Redis only once, on embedded.New. Pass this only to
// point the HTTP layer at a DIFFERENT Redis than the engine's ephemeral store.
func WithRedis(rd *redis.Client) Option {
	return func(s *Service) { s.rd = rd }
}

// WithRateLimiter overrides AuthKit's automatic rate limiter. ADVANCED/TEST ONLY:
// normal deployments let AuthKit own the policy (Redis-backed when WithRedis is
// supplied, in-memory otherwise) and must not inject a custom limiter.
func WithRateLimiter(rl RateLimiter) Option {
	return func(s *Service) { s.rl = rl; s.rlExplicit = true }
}

// WithRateLimitOverrides overlays bucket-specific limits onto AuthKit's built-in
// defaults (DefaultRateLimits, #242) — a host tunes one or a few buckets (e.g.
// RLPasswordLogin) without owning or re-materializing the whole ~55-bucket
// table. AuthKit still auto-selects the backend (Redis when WithRedis/the
// engine's Redis is wired, in-memory otherwise) exactly as it would with no
// options. Repeated calls merge (last write per bucket wins); an explicit
// WithRateLimiter/WithoutRateLimiter takes over the limiter entirely and makes
// these overrides moot (they're never consulted).
func WithRateLimitOverrides(overrides map[string]ratelimit.Limit) Option {
	return func(s *Service) {
		if s.rlOverrides == nil {
			s.rlOverrides = make(map[string]ratelimit.Limit, len(overrides))
		}
		for bucket, lim := range overrides {
			s.rlOverrides[bucket] = lim
		}
	}
}

// WithoutRateLimiter disables rate limiting. ADVANCED/TEST ONLY: never use in
// production — it removes brute-force and spam protection.
func WithoutRateLimiter() Option {
	return func(s *Service) { s.rl = nil; s.rlExplicit = true }
}

// WithTrustedProxies is the normal knob for deployments behind a reverse proxy or
// CDN: AuthKit derives the client IP (for rate limiting + auditing) from forwarded
// headers (CF-Connecting-IP / X-Forwarded-For) ONLY when the immediate peer is in
// one of the given trusted-proxy CIDRs; otherwise it uses the direct peer
// (RemoteAddr). With no trusted proxies the safe RemoteAddr default applies. An
// invalid CIDR fails NewServer rather than silently mis-trusting a proxy.
func WithTrustedProxies(cidrs ...string) Option {
	return func(s *Service) {
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
	return func(s *Service) {
		if fn == nil {
			fn = DefaultClientIP()
		}
		s.clientIP = fn
	}
}

// WithLanguageConfig sets the i18n language configuration.
func WithLanguageConfig(cfg LanguageConfig) Option {
	return func(s *Service) { s.langCfg = &cfg }
}
