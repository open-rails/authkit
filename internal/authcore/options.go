package authcore

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	authkit "github.com/open-rails/authkit"
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

// WithRedis makes the ephemeral store Redis-backed, namespaced by the
// deployment's Ephemeral.KeyPrefix (#307). Wins over WithEphemeralStore.
func WithRedis(rd *redis.Client) Option {
	return func(s *Service) { s.redisClient = rd }
}

// WithApplicationsHTTPClient overrides the outbound HTTP client used by
// application self-registration (#264) for application.json and JWKS fetches.
// The default is timeout-bounded, refuses redirects, and SSRF-guards its dials
// outside dev-like environments — override only for tests or custom transport
// needs (proxy, mTLS).
func WithApplicationsHTTPClient(c *http.Client) Option {
	return func(s *Service) { s.appHTTPClient = c }
}

// WithApplicationAdmission injects a host admission predicate consulted before
// any application self-registration fetch (#264): return a non-nil error to
// refuse the attempt (surfaced as registration-disabled). This is where
// host-side anti-squat cost gates plug in; authkit's own gates (rate limits,
// domain proof) apply regardless.
func WithApplicationAdmission(pred func(ctx context.Context, domain string) error) Option {
	return func(s *Service) { s.appAdmission = pred }
}

// WithInstanceAdmission injects the host admission predicate consulted before
// any generated persona-instance creation (#263): MayCreateInstance(ctx,
// persona, instanceSlug, subject) — return a non-nil error to refuse (surfaced
// as group_creation_refused). Mirrors WithApplicationAdmission's split: this is
// where host-side COST gates plug in; authkit's own anti-squat gates (per-IP +
// per-user creation velocity limits, reserved-slug escalation) apply regardless.
//
// The predicate receives the NORMALIZED slug (#269): a policy gate that cannot
// see WHAT is being claimed is half a gate. ReservedSlugs expresses "creatable
// only by an escalated caller"; a host that needs "never creatable through this
// route, by anyone" — a namespace its own bootstrap owns — can only say so here.
func WithInstanceAdmission(pred func(ctx context.Context, persona, instanceSlug, subject string) error) Option {
	return func(s *Service) { s.instanceAdmission = pred }
}

// WithEntitlements sets the entitlements provider.
func WithEntitlements(p EntitlementsProvider) Option { return func(s *Service) { s.entitlements = p } }

// WithDelegatedAuthorization injects the host's delegation authorizer for the
// delegated-token mint route (#261/#277). Its grant is the complete authority
// AuthKit signs; AuthKit never interprets it (same idiom as WithEntitlements).
func WithDelegatedAuthorization(a DelegationAuthorizer) Option {
	return func(s *Service) { s.delegationAuthorizer = a }
}

// WithEmailSender sets the email provider.
func WithEmailSender(sender EmailSender) Option { return func(s *Service) { s.email = sender } }

// WithClock replaces the engine clock used for TTL and grace-window decisions.
func WithClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// WithSolanaSNSResolver replaces the SNS primary-name resolver used after a
// verified Solana link.
func WithSolanaSNSResolver(r SolanaSNSResolver) Option {
	return func(s *Service) {
		if r != nil {
			s.solanaSNSResolver = r
		}
	}
}

// WithSMSSender sets the SMS provider.
func WithSMSSender(sender SMSSender) Option { return func(s *Service) { s.sms = sender } }

// WithNameAdmission supplies a side-effect-free host namespace policy for creation and rename.
func WithNameAdmission(check func(context.Context, authkit.NameAdmissionRequest) error) Option {
	return func(s *Service) { s.nameAdmission = check }
}
