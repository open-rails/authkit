package authhttp

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
)

// Test-only embedded.Deps builders so a call site names only what it wires.
type coreOpt func(*embedded.Deps)

func withPostgres(pool *pgxpool.Pool) coreOpt { return func(d *embedded.Deps) { d.Postgres = pool } }
func withRedis(rd *redis.Client) coreOpt      { return func(d *embedded.Deps) { d.Redis = rd } }
func withEphemeralStore(s embedded.EphemeralStore) coreOpt {
	return func(d *embedded.Deps) { d.EphemeralStore = s }
}
func withEmailSender(s embedded.EmailSender) coreOpt { return func(d *embedded.Deps) { d.Email = s } }
func withSMSSender(s embedded.SMSSender) coreOpt     { return func(d *embedded.Deps) { d.SMS = s } }
func withEntitlements(p embedded.EntitlementsProvider) coreOpt {
	return func(d *embedded.Deps) { d.Entitlements = p }
}
func withClock(now func() time.Time) coreOpt { return func(d *embedded.Deps) { d.Clock = now } }
func withSolanaSNSResolver(r embedded.SolanaSNSResolver) coreOpt {
	return func(d *embedded.Deps) { d.SolanaSNSResolver = r }
}
func withDelegatedAuthorization(a embedded.DelegationAuthorizer) coreOpt {
	return func(d *embedded.Deps) { d.DelegatedAuthorization = a }
}
func withInstanceAdmission(pred func(ctx context.Context, group authkit.GroupRef, subject string) error) coreOpt {
	return func(d *embedded.Deps) { d.InstanceAdmission = pred }
}
func withNameAdmission(check func(context.Context, authkit.NameAdmissionRequest) error) coreOpt {
	return func(d *embedded.Deps) { d.NameAdmission = check }
}

func depsOf(opts ...coreOpt) embedded.Deps {
	var d embedded.Deps
	for _, o := range opts {
		if o != nil {
			o(&d)
		}
	}
	return d
}

// coreFromConfig is embedded.NewFromConfig with the pool positional and Deps
// composed from options.
func coreFromConfig(cfg embedded.Config, pool *pgxpool.Pool, opts ...coreOpt) (*embedded.Service, error) {
	return embedded.NewFromConfig(cfg, depsOf(append([]coreOpt{withPostgres(pool)}, opts...)...))
}
