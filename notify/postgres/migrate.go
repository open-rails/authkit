// Package postgres implements notify's durable inbox on a host-owned PostgreSQL
// pool. Hosts explicitly migrate before use and authorize every recipient. It
// starts no workers, sends no messages and never owns the host's pool.
package postgres

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

var migrationPaths = []string{"migrations/001_inbox.sql", "migrations/002_action_requested.sql", "migrations/003_receipt_state.sql", "migrations/004_app_visibility.sql", "migrations/005_app_erasure.sql", "migrations/006_producer_mutations.sql"}

func schemaName(schema string) (string, error) {
	if schema == "" || len(schema) > 63 || strings.TrimSpace(schema) != schema || strings.ContainsRune(schema, 0) {
		return "", fmt.Errorf("notify: a nonempty PostgreSQL schema is required")
	}
	return pgx.Identifier{schema}.Sanitize(), nil
}

// Migrate applies this library's versioned migrations in a transaction. The
// host creates the schema and supplies a pool with DDL permission.
func Migrate(ctx context.Context, pool *pgxpool.Pool, schema string) error {
	if pool == nil {
		return fmt.Errorf("notify: migration pool is required")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	err = migrate(ctx, schema, func(query string, args ...any) error { _, err := tx.Exec(ctx, query, args...); return err }, func(query string) (int, error) { var v int; err := tx.QueryRow(ctx, query).Scan(&v); return v, err })
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// MigrateDB is Migrate for a host's database/sql DDL connection.
func MigrateDB(ctx context.Context, db *sql.DB, schema string) error {
	if db == nil {
		return fmt.Errorf("notify: migration database is required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	err = migrate(ctx, schema, func(query string, args ...any) error { _, err := tx.ExecContext(ctx, query, args...); return err }, func(query string) (int, error) {
		var v int
		err := tx.QueryRowContext(ctx, query).Scan(&v)
		return v, err
	})
	if err != nil {
		return err
	}
	return tx.Commit()
}

func migrate(ctx context.Context, schema string, exec func(string, ...any) error, version func(string) (int, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name, err := schemaName(schema)
	if err != nil {
		return err
	}
	if err = exec(`SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, schema+"/helpers/notify/migrate"); err != nil {
		return err
	}
	ledger := name + `.notify_migrations`
	if err = exec(`CREATE TABLE IF NOT EXISTS ` + ledger + ` (version integer PRIMARY KEY)`); err != nil {
		return err
	}
	v, err := version(`SELECT coalesce(max(version),0) FROM ` + ledger)
	if err != nil {
		return err
	}
	// Older readers coexist with additive future migrations. Each version and
	// its ledger entry commit atomically under the migration lock.
	for i, path := range migrationPaths {
		version := i + 1
		if version <= v {
			continue
		}
		b, err := migrations.ReadFile(path)
		if err != nil {
			return err
		}
		if err = exec(strings.ReplaceAll(string(b), "{{schema}}", name)); err != nil {
			return fmt.Errorf("notify: migration %d: %w", version, err)
		}
		if err = exec(`INSERT INTO `+ledger+`(version) VALUES ($1)`, version); err != nil {
			return err
		}
	}
	return nil
}
