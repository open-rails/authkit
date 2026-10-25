package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Validate verifies the notification ledger and required columns using reads
// only. It neither creates the schema nor runs pending migrations. Newer
// additive migrations are accepted when every migration this reader needs is
// present; an incomplete older ledger is not accepted.
func Validate(ctx context.Context, pool *pgxpool.Pool, schema string) error {
	if ctx == nil {
		return fmt.Errorf("notify: context is required")
	}
	if pool == nil {
		return fmt.Errorf("notify: pool is required")
	}
	name, err := schemaName(schema)
	if err != nil {
		return err
	}
	needed := func(err error) error {
		return fmt.Errorf("notify: schema %q requires migration; run postgres.Migrate: %w", schema, err)
	}
	rows, err := pool.Query(ctx, `SELECT version FROM `+name+`.notify_migrations`)
	if err != nil {
		return needed(err)
	}
	applied := map[int]bool{}
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			rows.Close()
			return needed(err)
		}
		applied[version] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return needed(err)
	}
	for i := range migrationPaths {
		if !applied[i+1] {
			return needed(fmt.Errorf("missing migration %d", i+1))
		}
	}
	if _, err := pool.Exec(ctx, `SELECT `+columns+` FROM `+name+`.notify_items LIMIT 0`); err != nil {
		return needed(err)
	}
	if _, err := pool.Exec(ctx, `SELECT producer_hash FROM `+name+`.notify_items LIMIT 0`); err != nil {
		return needed(err)
	}
	if _, err := pool.Exec(ctx, `SELECT scope,audience,recipient,erased_at FROM `+name+`.notify_recipients LIMIT 0`); err != nil {
		return needed(err)
	}
	if _, err := pool.Exec(ctx, `SELECT scope,audience,recipient,app_id,source,source_scope FROM `+name+`.notify_app_erasures LIMIT 0`); err != nil {
		return needed(err)
	}
	return nil
}
