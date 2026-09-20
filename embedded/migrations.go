package embedded

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	internalmigrations "github.com/open-rails/authkit/internal/migrations/postgres"
	"github.com/open-rails/migratekit"
)

// ApplyMigrations applies AuthKit's PostgreSQL migrations to pool.
//
// AuthKit owns its migration source and migratekit runner. The host supplies
// the database pool and the schema name, then constructs the Client after
// this function returns successfully. The schema is created by migratekit;
// callers must not create it separately. An empty schema selects AuthKit's
// default "profiles" schema.
func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool, schema string) error {
	if pool == nil {
		return errors.New("authkit: ApplyMigrations requires a non-nil *pgxpool.Pool")
	}
	normalized, err := normalizeSchemaName(schema)
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
	return nil
}
