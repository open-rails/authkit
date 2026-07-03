package authcore

import (
	"github.com/ClickHouse/clickhouse-go/v2"
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

// WithEphemeralStore sets the ephemeral store. Redis-backedness is discovered by
// type assertion (EphemeralRedisClient), not a mode string (#236).
func WithEphemeralStore(store EphemeralStore) Option {
	return func(s *Service) { s.ephemeralStore = store }
}

// WithEntitlements sets the entitlements provider.
func WithEntitlements(p EntitlementsProvider) Option { return func(s *Service) { s.entitlements = p } }

// WithClickHouse wires a ClickHouse connection AuthKit uses directly to record
// and read auth/session-history events (the user_auth_session_events table; see
// migrations/clickhouse). No ClickHouse means no session-event history and the
// admin sign-in routes report it unavailable.
func WithClickHouse(conn clickhouse.Conn) Option {
	return func(s *Service) {
		s.authlog = newClickHouseAuthLog(conn)
	}
}

// WithEmailSender sets the email provider.
func WithEmailSender(sender EmailSender) Option { return func(s *Service) { s.email = sender } }

// WithSMSSender sets the SMS provider.
func WithSMSSender(sender SMSSender) Option { return func(s *Service) { s.sms = sender } }
