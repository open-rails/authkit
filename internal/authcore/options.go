package authcore

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit/internal/db"
)

// Option configures a Service at construction time. Options are applied inside
// NewFromConfig / NewService, after the base service is built — the replacement
// for the removed chainable WithX builder methods (#108). Data/policy belongs in
// Config; every runtime DEPENDENCY is an Option.
type Option func(*Service)

// WithPostgres attaches the pgx pool and binds the schema-qualified querier.
// NewFromConfig applies this automatically from its required pg argument.
func WithPostgres(pool *pgxpool.Pool) Option {
	return func(s *Service) {
		s.pg = pool
		if pool != nil {
			s.q = db.New(db.ForSchema(pool, s.dbSchema()))
		}
	}
}

// WithEphemeralStore sets the ephemeral store + mode (empty mode => memory).
func WithEphemeralStore(store EphemeralStore, mode EphemeralMode) Option {
	return func(s *Service) {
		if mode == "" {
			mode = EphemeralMemory
		}
		s.ephemeralStore = store
		s.ephemeralMode = mode
	}
}

// WithEntitlements sets the entitlements provider.
func WithEntitlements(p EntitlementsProvider) Option { return func(s *Service) { s.entitlements = p } }

// WithAPIKeyResourceAuthorizer authorizes non-empty resource scopes on API-key
// minting. Without this hook, resource-scoped API-key minting fails closed.
func WithAPIKeyResourceAuthorizer(a APIKeyResourceAuthorizer) Option {
	return func(s *Service) { s.apiKeyResource = a }
}

// WithAuthLogger sets the session-event audit sink.
func WithAuthLogger(l AuthEventLogger) Option { return func(s *Service) { s.authlog = l } }

// WithEmailSender sets the email provider.
func WithEmailSender(sender EmailSender) Option { return func(s *Service) { s.email = sender } }

// WithSMSSender sets the SMS provider.
func WithSMSSender(sender SMSSender) Option { return func(s *Service) { s.sms = sender } }

// WithSolanaSNSResolver turns on Solana Name Service resolution using the
// host-provided resolver (SNS is off when no resolver is supplied).
func WithSolanaSNSResolver(r SolanaSNSResolver) Option {
	return func(s *Service) { s.opts.SolanaSNSResolver = r }
}

// WithDBTXWrapper re-binds the querier through wrap (a decorator over the
// schema-rewriting db.DBTX). Test seam for counting/spy queriers; must be
// applied after WithPostgres (NewFromConfig applies pg first).
func WithDBTXWrapper(wrap func(db.DBTX) db.DBTX) Option {
	return func(s *Service) {
		if s.pg == nil || wrap == nil {
			return
		}
		s.q = db.New(wrap(db.ForSchema(s.pg, s.dbSchema())))
	}
}
