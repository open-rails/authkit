package authhttp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	core "github.com/open-rails/authkit/core"
	"github.com/redis/go-redis/v9"
)

// Server is the net/http mounting wrapper around core.Service. It is the
// PREFERRED name for this type — it disambiguates from core.Service, which is a
// different type (the issuing engine). `Service` is retained as a
// backward-compatible alias so existing embedders need no changes (#109).
type Server = Service

// Option configures a Server at construction. Options are applied INSIDE
// NewServer, before the Server is returned or validated, so a half-built Server
// is never observable. This is the preferred replacement for the chainable
// WithX methods, whose mutate-and-return-self form allowed a partially
// configured Server to be used (#108).
type Option func(*Server)

// NewServer constructs the auth Server. Postgres is REQUIRED: the durable user/
// org/role store has no in-memory fallback, so a pg-less Server cannot do
// anything useful — it is a positional argument the type system enforces (#106).
// (Pure token verification with no storage uses authhttp.NewVerifier /
// authkit/verify instead.) Optional dependencies and behavior are supplied as
// functional options:
//
//	srv, err := authhttp.NewServer(cfg, pg,
//	    authhttp.WithRedis(rdb),
//	    authhttp.WithEmailSender(mailer),
//	)
//
// Prefer NewServer over the older NewService(cfg).WithPostgres(pg)... builder.
func NewServer(cfg core.Config, pg *pgxpool.Pool, opts ...Option) (*Server, error) {
	if pg == nil {
		return nil, errors.New("authkit: NewServer requires a non-nil *pgxpool.Pool (Postgres is mandatory)")
	}
	s, err := newServer(cfg)
	if err != nil {
		return nil, err
	}
	s.WithPostgres(pg)
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	if err := s.validate(cfg); err != nil {
		return nil, err
	}
	return s, nil
}

// validate enforces the CONDITIONAL dependency requirements for the configured
// feature set. pg is already guaranteed by NewServer's signature; this covers
// deps whose necessity depends on configuration. Only NewServer runs it (the
// lenient NewService path is unchanged), so it never breaks existing callers.
func (s *Server) validate(cfg core.Config) error {
	env := strings.ToLower(strings.TrimSpace(cfg.Environment))
	if env == "prod" || env == "production" {
		if s.rd == nil {
			return fmt.Errorf("authkit: production requires a Redis-compatible ephemeral store — pass authhttp.WithRedis(...); a memory store is dev-only")
		}
	}
	return nil
}

// --- Functional-option forms of the dependency injectors (#108). Each mirrors
// the identically named chainable WithX method (which remains for back-compat).
// Prefer these inside NewServer. ---

// WithRedis supplies the Redis client (ephemeral store + OIDC state cache).
func WithRedis(rd *redis.Client) Option { return func(s *Server) { s.WithRedis(rd) } }

// WithEmailSender supplies the email provider.
func WithEmailSender(es core.EmailSender) Option { return func(s *Server) { s.WithEmailSender(es) } }

// WithSMSSender supplies the SMS provider.
func WithSMSSender(sender core.SMSSender) Option { return func(s *Server) { s.WithSMSSender(sender) } }

// WithEntitlements supplies the entitlements provider.
func WithEntitlements(p core.EntitlementsProvider) Option {
	return func(s *Server) { s.WithEntitlements(p) }
}

// WithRateLimiter overrides the default in-memory rate limiter.
func WithRateLimiter(rl RateLimiter) Option { return func(s *Server) { s.WithRateLimiter(rl) } }

// WithoutRateLimiter disables rate limiting (option form of DisableRateLimiter).
func WithoutRateLimiter() Option { return func(s *Server) { s.DisableRateLimiter() } }

// WithClientIPFunc sets the client-IP extraction strategy (for rate limiting + auditing).
func WithClientIPFunc(fn ClientIPFunc) Option { return func(s *Server) { s.WithClientIPFunc(fn) } }

// WithAuthLogger supplies the session-event audit sink.
func WithAuthLogger(l core.AuthEventLogger) Option { return func(s *Server) { s.WithAuthLogger(l) } }

// WithAuthLogReader supplies the session-event reader (admin sign-in views).
func WithAuthLogReader(r core.AuthEventLogReader) Option {
	return func(s *Server) { s.WithAuthLogReader(r) }
}

// WithLanguageConfig sets the i18n language configuration.
func WithLanguageConfig(cfg LanguageConfig) Option {
	return func(s *Server) { s.WithLanguageConfig(cfg) }
}

// WithErrorLogger supplies the internal-error observability hook.
func WithErrorLogger(fn func(context.Context, InternalErrorEvent)) Option {
	return func(s *Server) { s.WithErrorLogger(fn) }
}

// WithSolanaDomain sets the domain used in SIWS sign-in messages.
func WithSolanaDomain(domain string) Option { return func(s *Server) { s.WithSolanaDomain(domain) } }

// WithEphemeralStore overrides the ephemeral store + mode.
func WithEphemeralStore(store core.EphemeralStore, mode core.EphemeralMode) Option {
	return func(s *Server) { s.WithEphemeralStore(store, mode) }
}
