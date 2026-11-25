package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/logx"
	internalmigrations "github.com/open-rails/authkit/internal/migrations/postgres"
	riverhelpers "github.com/open-rails/helpers/river"
	"github.com/open-rails/migratekit"
)

// Migrate creates or upgrades AuthKit's tables in db.Schema and River's in
// db.RiverSchema through pool, whose role then owns them. New runs it before
// anything else touches the database; replicas booting together serialize on
// advisory locks, so it is safe to run concurrently. A schema a newer build
// already migrated passes unchanged: migrations this build does not know are
// left as they are.
type MigrationOptions struct {
	// Tenancy is the deployment's Config.Tenancy. Single-tenant, Migrate
	// creates the one tenant a database without one needs (under
	// LegacyTenantID, else a new ID), adopts the one a database holds, and
	// refuses a database with more, or with another than LegacyTenantID.
	Tenancy config.Tenancy
	// LegacyTenantID names the tenant that adopts the accounts of a database
	// from before tenants (AuthKit before v1.30). Multi-tenant such a
	// database refuses to migrate without it; single-tenant a new ID is
	// used. It never merges directories.
	LegacyTenantID iam.TenantID
	// Logger receives the migrators' logs. Nil is slog.Default().
	Logger *slog.Logger
}

func Migrate(ctx context.Context, pool *pgxpool.Pool, db config.DatabaseConfig, options ...MigrationOptions) error {
	if pool == nil {
		return errors.New("authkit: migrating needs Deps.Postgres")
	}
	if len(options) > 1 {
		return errors.New("authkit: Migrate accepts at most one MigrationOptions")
	}
	var opts MigrationOptions
	if len(options) == 1 {
		opts = options[0]
	}
	log := logx.Or(opts.Logger)
	legacy := opts.LegacyTenantID
	if legacy.IsZero() && opts.Tenancy == config.TenancySingle {
		legacy = iam.NewTenantID()
	}
	if !legacy.IsZero() {
		// The migration setting belongs only to this owned handle. Never mutate
		// the host pool or interpolate a configured ID into migration SQL.
		cfg := pool.Config().Copy()
		if cfg.ConnConfig.RuntimeParams == nil {
			cfg.ConnConfig.RuntimeParams = map[string]string{}
		}
		cfg.ConnConfig.RuntimeParams["authkit.legacy_tenant_id"] = legacy.String()
		owned, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			return fmt.Errorf("authkit: prepare tenant migration connection: %w", err)
		}
		defer owned.Close()
		pool = owned
	}
	normalized, err := config.NormalizeSchema(db.Schema)
	if err != nil {
		return err
	}
	riverSchema, err := config.NormalizeRiverSchema(db.RiverSchema, normalized)
	if err != nil {
		return err
	}
	migrations, err := migratekit.LoadFromFS(internalmigrations.FS)
	if err != nil {
		return fmt.Errorf("authkit: load PostgreSQL migrations: %w", err)
	}
	migrator, err := migratekit.NewPostgresFromPGXPool(pool, "authkit")
	if err != nil {
		return fmt.Errorf("authkit: create PostgreSQL migrator: %w", err)
	}
	defer migrator.Close()
	// Strict integrity: an edited applied migration refuses unless the schema
	// is unchanged.
	migrator = migrator.WithSchema(normalized).WithStrictIntegrity().WithWarnFunc(migrationWarnings(ctx, log))
	if err := migrator.ApplyMigrations(ctx, migrations); err != nil {
		return fmt.Errorf("authkit: apply PostgreSQL migrations to schema %q: %w", normalized, err)
	}
	// The account inbox lives beside the accounts.
	if err := migrateNotifications(ctx, pool, normalized); err != nil {
		return fmt.Errorf("authkit: migrate the account inbox in schema %q: %w", normalized, err)
	}
	// River's tables, under the lock River initializers share; every insert
	// notifies its queue, so AuthKit's own fleet polls only as a backstop (#477).
	if err := riverhelpers.ApplyMigrations(ctx, pool, riverhelpers.MigrationOptions{Schema: riverSchema, Logger: log}); err != nil {
		return fmt.Errorf("authkit: migrate River: %w", err)
	}
	if opts.Tenancy == config.TenancySingle {
		if _, err := soleTenant(ctx, log, pool, db, opts.LegacyTenantID, true); err != nil {
			return err
		}
	}
	return nil
}

// migrationWarnings logs migratekit's warnings through log.
func migrationWarnings(ctx context.Context, log *slog.Logger) func(migratekit.Discrepancy) {
	return func(d migratekit.Discrepancy) {
		log.WarnContext(ctx, "migratekit: "+d.OneLine(), "kind", string(d.Kind), "migration", d.File, "key", d.Key)
	}
}
