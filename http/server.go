package authhttp

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/open-rails/authkit/embedded"
	memorylimiter "github.com/open-rails/authkit/ratelimit/memory"
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
		rl:       memorylimiter.New(ToMemoryLimits(DefaultRateLimits())),
		clientIP: DefaultClientIP(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	s.svc = coreSvc

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

// PermissionGroupAuthorizer authorizes one generated permission-group route.
type PermissionGroupAuthorizer func(r *http.Request, subjectID, persona, instanceSlug, perm string) (bool, error)

// WithPermissionGroupAuthorizer lets a host wrap generated group-route authz,
// for example to lazily materialize host-owned groups before checking Can.
func WithPermissionGroupAuthorizer(fn PermissionGroupAuthorizer) Option {
	return func(s *Server) { s.groupCanFn = fn }
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

