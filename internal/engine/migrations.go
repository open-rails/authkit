package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
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
type MigrationOptions struct {
	// LegacyTenantID explicitly adopts an existing single directory into this
	// canonical business tenant. It never invents a tenant or merges directories.
	LegacyTenantID iam.TenantID
}

func Migrate(ctx context.Context, pool *pgxpool.Pool, db config.DatabaseConfig, options ...MigrationOptions) error {
	if pool == nil {
		return errors.New("authkit: migrating needs Deps.Postgres")
	}
	if len(options) > 1 {
		return errors.New("authkit: Migrate accepts at most one MigrationOptions")
	}
	if len(options) == 1 && !options[0].LegacyTenantID.IsZero() {
		// The migration setting belongs only to this owned handle. Never mutate
		// the host pool or interpolate a configured ID into migration SQL.
		cfg := pool.Config().Copy()
		if cfg.ConnConfig.RuntimeParams == nil {
			cfg.ConnConfig.RuntimeParams = map[string]string{}
		}
		cfg.ConnConfig.RuntimeParams["authkit.legacy_tenant_id"] = options[0].LegacyTenantID.String()
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
	return retireAccountDeletionJobs(ctx, pool, normalized, riverSchema)
}

// Lifecycle and required cleanup receipts are authoritative before jobs retire. Upgrade each
// fleet while old writers are stopped; an active old worker or an orphan timer
// fails closed rather than abandoning unverified work.
func retireAccountDeletionJobs(ctx context.Context, pool *pgxpool.Pool, schema, riverSchema string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	deletions := pgx.Identifier{schema, "account_deletions"}.Sanitize()
	jobs := pgx.Identifier{riverSchema, "river_job"}.Sanitize()
	// Keep validation and retirement atomic with lifecycle GC and River fetches.
	// These locks are held only for this short, explicit migration transaction.
	if _, err := tx.Exec(ctx, "LOCK TABLE "+deletions+" IN SHARE MODE; LOCK TABLE "+jobs+" IN SHARE ROW EXCLUSIVE MODE"); err != nil {
		return err
	}
	var running, orphan bool
	err = tx.QueryRow(ctx, `SELECT
		EXISTS (SELECT 1 FROM `+jobs+` j WHERE j.kind IN ('authkit_account_finalize','authkit_account_delivery') AND j.args->>'schema'=$1 AND j.state='running'),
		EXISTS (SELECT 1 FROM `+jobs+` j WHERE j.kind='authkit_account_finalize' AND j.args->>'schema'=$1
		  AND j.state IN ('available','pending','retryable','scheduled')
		  AND NOT EXISTS (SELECT 1 FROM `+deletions+` d WHERE d.id::text=j.args->>'deletion_id'))`, schema).Scan(&running, &orphan)
	if err != nil {
		return err
	}
	if running {
		return fmt.Errorf("authkit: legacy account deletion job is running in River schema %q; stop old account workers and retry migration", riverSchema)
	}
	if orphan {
		return fmt.Errorf("authkit: account deletion timer has no canonical deletion record in schema %q; repair its lifecycle state before migrating", schema)
	}
	_, err = tx.Exec(ctx, "DELETE FROM "+jobs+`
		WHERE kind IN ('authkit_account_finalize','authkit_account_delivery') AND args->>'schema'=$1
		AND state IN ('available','pending','retryable','scheduled')`, schema)
	if err != nil {
		return fmt.Errorf("authkit: retire account deletion timers: %w", err)
	}
	return tx.Commit(ctx)
}
