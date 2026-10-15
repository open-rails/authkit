package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/open-rails/authkit/internal/config"
	internalmigrations "github.com/open-rails/authkit/internal/migrations/postgres"
	riverhelpers "github.com/open-rails/helpers/river"
	"github.com/open-rails/migratekit"
)

var ErrMigrationsRequired = errors.New("authkit: database migrations are required")

// validateMigrations reads the existing ledger and River schema. Unlike
// MigrateKit.Status it does not create or upgrade migration tracking tables.
func validateMigrations(ctx context.Context, pool *pgxpool.Pool, db config.DatabaseConfig) error {
	if pool == nil {
		return errors.New("authkit: validating migrations needs Deps.Postgres")
	}
	schema, err := config.NormalizeSchema(db.Schema)
	if err != nil {
		return err
	}
	riverSchema, err := config.NormalizeRiverSchema(db.RiverSchema)
	if err != nil {
		return err
	}
	chain, err := migratekit.LoadFromFS(internalmigrations.FS)
	if err != nil {
		return err
	}
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	m := migratekit.NewPostgres(sqlDB, "authkit").WithSchema(schema)
	if err := m.ValidateAllApplied(ctx, chain); err != nil {
		return migrationValidationError(err)
	}
	// A reused sequence number is not proof that this lineage was applied.
	// Older ledgers without names retain MigrateKit's existing compatibility.
	applied, err := m.AppliedRecords(ctx)
	if err != nil {
		return migrationValidationError(err)
	}
	for _, migration := range chain {
		record := applied[migratekit.Prefix(migration.Name)]
		if record.Filename != "" && record.Filename != migration.Name {
			return migrationValidationError(fmt.Errorf("schema %q has migration %q where %q is required", schema, record.Filename, migration.Name))
		}
	}
	if err := riverhelpers.ValidateMigrations(ctx, pool, riverSchema); err != nil {
		return migrationValidationError(err)
	}
	return nil
}

func migrationValidationError(err error) error {
	// Losing access to PostgreSQL is not evidence of an unapplied migration.
	var network net.Error
	var connect *pgconn.ConnectError
	var postgres *pgconn.PgError
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &network) || errors.As(err, &connect) ||
		errors.As(err, &postgres) && (strings.HasPrefix(postgres.Code, "08") || strings.HasPrefix(postgres.Code, "53") || strings.HasPrefix(postgres.Code, "57")) {
		return fmt.Errorf("authkit: validate database migrations: %w", err)
	}
	return fmt.Errorf("%w; run authkit.Migrate before application startup: %w", ErrMigrationsRequired, err)
}
