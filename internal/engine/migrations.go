package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/internal/config"
	sqlc "github.com/open-rails/authkit/internal/db"
	internalmigrations "github.com/open-rails/authkit/internal/migrations/postgres"
	"github.com/open-rails/authkit/internal/migrations/retired"
	"github.com/open-rails/migratekit"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
)

// Migrate creates or upgrades AuthKit's tables in db.Schema and River's in
// db.RiverSchema through pool, whose role then owns them. New runs it before
// anything else touches the database; replicas booting together serialize on
// advisory locks, so it is safe to run concurrently. A schema a newer build
// already migrated passes unchanged: migrations this build does not know are
// left as they are.
func Migrate(ctx context.Context, pool *pgxpool.Pool, db config.DatabaseConfig) error {
	if pool == nil {
		return errors.New("authkit: migrating needs Deps.Postgres")
	}
	normalized, err := config.NormalizeSchema(db.Schema)
	if err != nil {
		return err
	}
	riverSchema, err := config.NormalizeRiverSchema(db.RiverSchema)
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
	// is unchanged. A schema the v0.125–v0.148 chain built, whole or part-way,
	// is converted; one an older chain built is refused.
	migrator = migrator.WithSchema(normalized).WithStrictIntegrity()
	conversions, err := retired.Conversions(ctx, migrator, migrations)
	if err != nil {
		return fmt.Errorf("authkit: schema %q: %w", normalized, err)
	}
	migrator = migrator.WithConversions(conversions...)
	if err := migrator.ApplyMigrations(ctx, migrations); err != nil {
		return fmt.Errorf("authkit: apply PostgreSQL migrations to schema %q: %w", normalized, err)
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
	if err := sqlc.New(lockConn).AdvisoryLock(ctx, "river-migrations:"+riverSchema); err != nil {
		return fmt.Errorf("authkit: lock River migrations: %w", err)
	}

	// River owns its table migrations. Schema creation is deployment setup, and
	// the schema is always explicit instead of following the pool search_path.
	if _, err := pool.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+pgx.Identifier{riverSchema}.Sanitize()); err != nil {
		return fmt.Errorf("authkit: create River schema: %w", err)
	}
	riverMigrator, err := rivermigrate.New(riverpgxv5.New(pool), &rivermigrate.Config{Schema: riverSchema})
	if err != nil {
		return fmt.Errorf("authkit: construct River migrator: %w", err)
	}
	if _, err := riverMigrator.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		return fmt.Errorf("authkit: migrate River: %w", err)
	}
	return nil
}
