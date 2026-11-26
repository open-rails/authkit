package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/open-rails/migratekit"
)

// Validate verifies the inbox's migration ledger using reads only. It neither
// creates the schema nor runs pending migrations. Newer migrations are
// accepted when every migration this reader needs is applied unchanged.
func Validate(ctx context.Context, pool *pgxpool.Pool, schema string) error {
	if ctx == nil {
		return fmt.Errorf("notify: context is required")
	}
	if pool == nil {
		return fmt.Errorf("notify: pool is required")
	}
	list, err := chain(schema)
	if err != nil {
		return err
	}
	db := stdlib.OpenDBFromPool(pool)
	defer db.Close()
	m := migratekit.NewPostgres(db, app).WithSchema(schema)
	if err := m.ValidateAllApplied(ctx, list); err != nil {
		return fmt.Errorf("notify: schema %q requires migration; run postgres.Migrate: %w", schema, err)
	}
	records, err := m.AppliedRecords(ctx)
	if err != nil {
		return fmt.Errorf("notify: read the migrations of schema %q: %w", schema, err)
	}
	for _, migration := range list {
		record := records[migratekit.Prefix(migration.Name)]
		if record.Filename != migration.Name || record.Digest != "" && record.Digest != migratekit.ContentDigest(migration.Content) {
			return fmt.Errorf("notify: schema %q ran %s with other content; an applied migration never changes, so rebuild the inbox: %w", schema, migration.Name, migratekit.ErrMigrationEdited)
		}
	}
	return nil
}
