package authcore

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// Test-only Deps builders: the engine takes one Deps value; tests compose it
// from these so a call site names only what it wires.
type Option func(*Deps)

func WithPostgres(pool *pgxpool.Pool) Option { return func(d *Deps) { d.Postgres = pool } }
func WithRedis(rd *redis.Client) Option      { return func(d *Deps) { d.Redis = rd } }
func WithEphemeralStore(store EphemeralStore) Option {
	return func(d *Deps) { d.EphemeralStore = store }
}
func WithEmailSender(s EmailSender) Option           { return func(d *Deps) { d.Email = s } }
func WithSMSSender(s SMSSender) Option               { return func(d *Deps) { d.SMS = s } }
func WithEntitlements(p EntitlementsProvider) Option { return func(d *Deps) { d.Entitlements = p } }
func WithClock(now func() time.Time) Option          { return func(d *Deps) { d.Clock = now } }
func WithSolanaSNSResolver(r SolanaSNSResolver) Option {
	return func(d *Deps) { d.SolanaSNSResolver = r }
}
func WithApplicationsHTTPClient(c *http.Client) Option { return func(d *Deps) { d.OutboundHTTP = c } }
func WithDelegatedAuthorization(a DelegationAuthorizer) Option {
	return func(d *Deps) { d.DelegatedAuthorization = a }
}
func WithApplicationAdmission(pred func(ctx context.Context, domain string) error) Option {
	return func(d *Deps) { d.ApplicationAdmission = pred }
}
func WithInstanceAdmission(pred func(ctx context.Context, persona, instanceSlug, subject string) error) Option {
	return func(d *Deps) { d.InstanceAdmission = pred }
}

func depsOf(opts ...Option) Deps {
	var d Deps
	for _, o := range opts {
		if o != nil {
			o(&d)
		}
	}
	return d
}

// newFromConfig is NewFromConfig with the pool positional and Deps composed
// from options, the shape most tests read best.
func newFromConfig(cfg Config, pool *pgxpool.Pool, opts ...Option) (*Service, error) {
	return NewFromConfig(cfg, depsOf(append([]Option{WithPostgres(pool)}, opts...)...))
}
