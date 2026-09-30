package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/internal/db"
	internalmigrations "github.com/open-rails/authkit/internal/migrations/postgres"
	"github.com/open-rails/authkit/internal/migrations/retired"
	"github.com/open-rails/migratekit"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
)

// MigrateOptions mirrors authkit.MigrateOptions.
type MigrateOptions struct {
	Schema      string
	River       *RiverOwnership
	RiverSchema string
	RuntimePool *pgxpool.Pool
}

// Migrate applies AuthKit's PostgreSQL migrations; see authkit.Migrate.
func Migrate(ctx context.Context, pool *pgxpool.Pool, opts MigrateOptions) error {
	var riverCfg RiverConfig
	if opts.River == nil || !opts.River.fromHost {
		var err error
		riverCfg, err = normalizeRiverConfig(RiverConfig{Schema: opts.RiverSchema})
		if err != nil {
			return err
		}
	}
	if pool == nil {
		return errors.New("authkit: Migrate requires a non-nil *pgxpool.Pool")
	}
	normalized, err := normalizeSchemaName(opts.Schema)
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
	// Strict integrity: an edited applied migration refuses unless the schema
	// is unchanged. Databases built by a retired baseline are converted.
	migrator = migrator.WithSchema(normalized).WithStrictIntegrity().WithConversions(retired.Conversions()...)
	if err := migrator.ApplyMigrations(ctx, migrations); err != nil {
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
	if err := db.New(lockConn).AdvisoryLock(ctx, "river-migrations:"+riverCfg.Schema); err != nil {
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

// probeMigrations fails fast at construction when AuthKit's migrations were
// never run: a definitive "users table missing" beats a cryptic mid-request
// `relation "users" does not exist`. Probe errors (connectivity, permissions)
// fail open; they surface elsewhere.
func (s *Engine) probeMigrations() error {
	if s.pg == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	exists, err := s.q.MigrationSchemaHasUsers(ctx, s.dbSchema())
	if err != nil || exists {
		return nil
	}
	return fmt.Errorf("authkit: schema %q has no users table — run authkit.Migrate before authkit.New", s.dbSchema())
}
