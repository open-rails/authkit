package authhttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
	memorylimiter "github.com/open-rails/authkit/ratelimit/memory"
	memorystore "github.com/open-rails/authkit/storage/memory"
	redisstore "github.com/open-rails/authkit/storage/redis"
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

// NewServer constructs the auth Server. Postgres is REQUIRED (the durable user/
// role and permission-group store has no in-memory fallback and is a positional argument the
// type system enforces (#106); pure token verification with no storage uses
// authhttp.NewVerifier / authkit/verify instead. Every optional dependency is a
// functional option:
//
//	srv, err := authhttp.NewServer(cfg, pg,
//	    authhttp.WithRedis(rdb),
//	    authhttp.WithEmailSender(mailer),
//	)
func NewServer(cfg embedded.Config, pg *pgxpool.Pool, opts ...Option) (*Server, error) {
	if pg == nil {
		return nil, errors.New("authkit: NewServer requires a non-nil *pgxpool.Pool (Postgres is mandatory)")
	}
	// HTTP-level defaults set BEFORE options so an option can override them.
	s := &Server{
		rl:       memorylimiter.New(ToMemoryLimits(DefaultRateLimits())),
		clientIP: DefaultClientIP(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}

	// Build the core service: default to an in-memory ephemeral store, which any
	// WithRedis/WithEphemeralStore option (collected in s.coreOpts) overrides
	// since later options win.
	coreOpts := append([]embedded.Option{embedded.WithEphemeralStore(memorystore.NewKV(), embedded.EphemeralMemory)}, s.coreOpts...)
	coreSvc, err := authcore.NewFromConfig(cfg, pg, coreOpts...)
	if err != nil {
		return nil, err
	}
	s.svc = coreSvc
	s.coreOpts = nil // transient; not retained past construction

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

	authProvidersByName, err := buildAuthProvidersMap(cfg.Identity.Providers, cfg.Identity.ProviderDescriptors)
	if err != nil {
		return nil, err
	}
	s.authProvidersByName = authProvidersByName
	s.oidcProviders = cfg.Identity.Providers
	s.providers = cfg.Identity.ProviderDescriptors
	s.memStateCache = memorystore.NewStateCache(15 * time.Minute)

	if err := s.validate(cfg); err != nil {
		return nil, err
	}
	return s, nil
}

// validate enforces the CONDITIONAL dependency requirements for the configured
// feature set (pg is already guaranteed by the signature).
func (s *Server) validate(cfg embedded.Config) error {
	env := strings.ToLower(strings.TrimSpace(cfg.Environment))
	if env == "prod" || env == "production" {
		if s.rd == nil {
			return fmt.Errorf("authkit: production requires a Redis-compatible ephemeral store — pass authhttp.WithRedis(...); a memory store is dev-only")
		}
	}
	return nil
}

// --- Functional options (#108). Core-dependency options accumulate into
// s.coreOpts (applied when the core service is built); HTTP-level options set
// fields on the Server directly. ---

// WithRedis supplies the Redis client: the ephemeral store + the OIDC state cache.
func WithRedis(rd *redis.Client) Option {
	return func(s *Server) {
		s.rd = rd
		if rd != nil {
			s.coreOpts = append(s.coreOpts, embedded.WithEphemeralStore(redisstore.NewKV(rd), embedded.EphemeralRedis))
		}
	}
}

// WithEphemeralStore overrides the ephemeral store + mode.
func WithEphemeralStore(store embedded.EphemeralStore, mode embedded.EphemeralMode) Option {
	return func(s *Server) { s.coreOpts = append(s.coreOpts, embedded.WithEphemeralStore(store, mode)) }
}

// WithEmailSender supplies the email provider.
func WithEmailSender(es embedded.EmailSender) Option {
	return func(s *Server) { s.coreOpts = append(s.coreOpts, embedded.WithEmailSender(es)) }
}

// WithSMSSender supplies the SMS provider.
func WithSMSSender(sender embedded.SMSSender) Option {
	return func(s *Server) { s.coreOpts = append(s.coreOpts, embedded.WithSMSSender(sender)) }
}

// WithEntitlements supplies the entitlements provider.
func WithEntitlements(p embedded.EntitlementsProvider) Option {
	return func(s *Server) { s.coreOpts = append(s.coreOpts, embedded.WithEntitlements(p)) }
}

// WithAPIKeyResourceAuthorizer supplies the host policy that authorizes
// non-empty resource scopes on API-key minting.
func WithAPIKeyResourceAuthorizer(a embedded.APIKeyResourceAuthorizer) Option {
	return func(s *Server) { s.coreOpts = append(s.coreOpts, embedded.WithAPIKeyResourceAuthorizer(a)) }
}

// PermissionGroupAuthorizer authorizes one generated permission-group route.
type PermissionGroupAuthorizer func(r *http.Request, subjectID, persona, instanceSlug, perm string) (bool, error)

// WithPermissionGroupAuthorizer lets a host wrap generated group-route authz,
// for example to lazily materialize host-owned groups before checking Can.
func WithPermissionGroupAuthorizer(fn PermissionGroupAuthorizer) Option {
	return func(s *Server) { s.groupCanFn = fn }
}

// WithAuthLogger supplies the session-event audit sink.
func WithAuthLogger(l embedded.AuthEventLogger) Option {
	return func(s *Server) { s.coreOpts = append(s.coreOpts, embedded.WithAuthLogger(l)) }
}

// WithSolanaSNSResolver enables Solana Name Service resolution via the host resolver.
func WithSolanaSNSResolver(r embedded.SolanaSNSResolver) Option {
	return func(s *Server) { s.coreOpts = append(s.coreOpts, embedded.WithSolanaSNSResolver(r)) }
}

// WithRateLimiter overrides the default in-memory rate limiter.
func WithRateLimiter(rl RateLimiter) Option { return func(s *Server) { s.rl = rl } }

// WithoutRateLimiter disables rate limiting.
func WithoutRateLimiter() Option { return func(s *Server) { s.rl = nil } }

// WithClientIPFunc sets the client-IP extraction strategy (rate limiting + auditing).
func WithClientIPFunc(fn ClientIPFunc) Option {
	return func(s *Server) {
		if fn == nil {
			fn = DefaultClientIP()
		}
		s.clientIP = fn
	}
}

// WithAuthLogReader supplies the session-event reader (admin sign-in views).
func WithAuthLogReader(r embedded.AuthEventLogReader) Option {
	return func(s *Server) { s.authlogr = r }
}

// WithLanguageConfig sets the i18n language configuration.
func WithLanguageConfig(cfg LanguageConfig) Option {
	return func(s *Server) { s.langCfg = &cfg }
}

// WithErrorLogger supplies the internal-error observability hook.
func WithErrorLogger(fn func(context.Context, InternalErrorEvent)) Option {
	return func(s *Server) { s.errorLogger = fn }
}

// WithSolanaDomain sets the domain used in SIWS sign-in messages.
func WithSolanaDomain(domain string) Option { return func(s *Server) { s.solanaDomain = domain } }
