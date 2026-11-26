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

// MigrationOptions configure Migrate.
type MigrationOptions struct {
	// Tenancy is the deployment's Config.Tenancy. Single-tenant, Migrate
	// creates the one tenant a database without one needs (under TenantID,
	// else a new ID), adopts the one a database holds, and refuses a database
	// with more, or with another than TenantID.
	Tenancy config.Tenancy
	// TenantID is the tenant a database holding none is created with: one
	// whose ID must match another system's, such as a ContentKit business.
	// Multi-tenant it is the deployment's default tenant (New passes
	// DefaultTenantID); a database already holding a tenant is unchanged.
	TenantID iam.TenantID
	// Logger receives the migrators' logs. Nil is slog.Default().
	Logger *slog.Logger
}

// Migrate creates or upgrades AuthKit's tables in db.Schema and River's in
// db.RiverSchema through pool, whose role then owns them. New runs it before
// anything else touches the database; replicas booting together serialize on
// advisory locks, so it is safe to run concurrently. A schema a newer build
// already migrated passes unchanged: migrations this build does not know are
// left as they are. Applied migrations never change: a schema that ran a
// migration whose file differs from this build's, as every schema built
// before v1.58.0 did, is refused before anything is applied
// (migratekit.ErrMigrationEdited) and is rebuilt.
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
	migrator = migrator.WithSchema(normalized).WithImmutableMigrations().WithWarnFunc(migrationWarnings(ctx, log))
	if err := migrator.ApplyMigrations(ctx, migrations); err != nil {
		if errors.Is(err, migratekit.ErrMigrationEdited) {
			return fmt.Errorf("authkit: %w", rebuild(normalized, err))
		}
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
		_, err := soleTenant(ctx, log, pool, db, opts.TenantID, true)
		return err
	}
	if !opts.TenantID.IsZero() {
		return firstTenant(ctx, log, pool, db, opts.TenantID)
	}
	return nil
}

// rebuild explains a schema whose applied migrations this build changed.
func rebuild(schema string, err error) error {
	return fmt.Errorf("schema %q ran migrations this build does not carry unchanged; AuthKit's migrations never change once released, and a database built before v1.58.0 is rebuilt: %w", schema, err)
}

// migrationWarnings logs migratekit's warnings through log.
func migrationWarnings(ctx context.Context, log *slog.Logger) func(migratekit.Discrepancy) {
	return func(d migratekit.Discrepancy) {
		log.WarnContext(ctx, "migratekit: "+d.OneLine(), "kind", string(d.Kind), "migration", d.File, "key", d.Key)
	}
}
