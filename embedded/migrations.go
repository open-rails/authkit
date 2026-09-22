package embedded

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	internalmigrations "github.com/open-rails/authkit/internal/migrations/postgres"
	"github.com/open-rails/migratekit"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
)

// MigrationOptions declares River ownership alongside AuthKit initialization.
// River uses the same declaration as Deps.River. Nil owns River initialization;
// RiverFromHost skips it. RiverSchema defaults to public, matching Config.River.
type MigrationOptions struct {
	River       *RiverOwnership
	RiverSchema string
	// RuntimePool identifies the existing database user that will run AuthKit.
	// When supplied, initialization grants that user runtime access directly.
	// Both pools must connect to the same database and remain host-owned.
	// Nil applies migrations without provisioning runtime privileges.
	RuntimePool *pgxpool.Pool
}

// ApplyMigrations applies AuthKit's PostgreSQL migrations to a privileged pool.
// It also initializes managed River unless RiverFromHost is declared. Runtime
// New and Start never run DDL; runtime credentials can be separately restricted.
//
// AuthKit owns its migration source and migratekit runner. The host supplies
// the database pool and the schema name, then constructs the Runtime after
// this function returns successfully. The schema is created by migratekit;
// callers must not create it separately. An empty schema selects AuthKit's
// default "profiles" schema.
func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool, schema string, options ...MigrationOptions) error {
	if len(options) > 1 {
		return errors.New("authkit: ApplyMigrations accepts at most one MigrationOptions")
	}
	var opts MigrationOptions
	if len(options) == 1 {
		opts = options[0]
	}
	var riverCfg RiverConfig
	if opts.River == nil || !opts.River.fromHost {
		var err error
		riverCfg, err = normalizeRiverConfig(RiverConfig{Schema: opts.RiverSchema})
		if err != nil {
			return err
		}
	}
	if pool == nil {
		return errors.New("authkit: ApplyMigrations requires a non-nil *pgxpool.Pool")
	}
	normalized, err := normalizeSchemaName(schema)
	if err != nil {
		return err
	}
	runtimeUser, err := migrationRuntimeUser(ctx, pool, opts.RuntimePool)
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
	if err := migrator.WithSchema(normalized).ApplyMigrations(ctx, migrations); err != nil {
		return fmt.Errorf("authkit: apply PostgreSQL migrations to schema %q: %w", normalized, err)
	}
	if opts.River != nil && opts.River.fromHost {
		return grantMigrationRuntimeAccess(ctx, pool, runtimeUser, normalized, "")
	}
	// River initializers share this database/schema lock protocol. The
	// dedicated session leaves even a one-connection caller pool free for DDL.
	lockConn, err := pgx.ConnectConfig(ctx, pool.Config().ConnConfig.Copy())
	if err != nil {
		return fmt.Errorf("authkit: connect River migration lock: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = lockConn.Close(cleanupCtx) // Closing the session releases its advisory lock.
	}()
	if _, err := lockConn.Exec(ctx, "SELECT pg_advisory_lock(hashtext(current_database()), hashtext($1))", "river-migrations:"+riverCfg.Schema); err != nil {
		return fmt.Errorf("authkit: lock River migrations: %w", err)
	}

	// River owns its table migrations. Schema creation is deployment setup, and
	// the schema is always explicit instead of following the pool search_path.
	if _, err := pool.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+pgx.Identifier{riverCfg.Schema}.Sanitize()); err != nil {
		return fmt.Errorf("authkit: create River schema: %w", err)
	}
	riverMigrator, err := rivermigrate.New(riverpgxv5.New(pool), &rivermigrate.Config{Schema: riverCfg.Schema})
	if err != nil {
		return fmt.Errorf("authkit: construct River migrator: %w", err)
	}
	if _, err := riverMigrator.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		return fmt.Errorf("authkit: migrate River: %w", err)
	}
	return grantMigrationRuntimeAccess(ctx, pool, runtimeUser, normalized, riverCfg.Schema)
}
