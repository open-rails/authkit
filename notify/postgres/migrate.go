// Package postgres implements notify's durable inbox on a host-owned PostgreSQL
// pool. Hosts explicitly migrate before use and authorize every recipient. It
// starts no workers, sends no messages and never owns the host's pool.
package postgres

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/migratekit"
)

//go:embed migrations/*.up.sql
var migrations embed.FS

// app names the inbox's migrations in migratekit's ledger.
const app = "authkit_notify"

func schemaName(schema string) (string, error) {
	if schema == "" || len(schema) > 63 || strings.TrimSpace(schema) != schema || strings.ContainsRune(schema, 0) {
		return "", fmt.Errorf("notify: a nonempty PostgreSQL schema is required")
	}
	return pgx.Identifier{schema}.Sanitize(), nil
}

// chain is the inbox's migrations rendered for schema. An applied migration
// never changes: a schema that ran one whose file differs is refused
// (migratekit.ErrMigrationEdited), as is an inbox built before AuthKit v1.58.0.
func chain(schema string) ([]migratekit.Migration, error) {
	name, err := schemaName(schema)
	if err != nil {
		return nil, err
	}
	dir, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return nil, err
	}
	list, err := migratekit.LoadFromFS(dir)
	if err != nil {
		return nil, err
	}
	for i := range list {
		list[i].Content = strings.ReplaceAll(list[i].Content, "{{schema}}", name)
	}
	return list, nil
}

// Migrate applies this library's migrations to schema, recording them in
// migratekit's ledger. The pool needs DDL permission.
func Migrate(ctx context.Context, pool *pgxpool.Pool, schema string) error {
	if pool == nil {
		return fmt.Errorf("notify: migration pool is required")
	}
	list, err := chain(schema)
	if err != nil {
		return err
	}
	m, err := migratekit.NewPostgresFromPGXPool(pool, app)
	if err != nil {
		return err
	}
	defer m.Close()
	return apply(ctx, m, schema, list)
}

// MigrateDB is Migrate for a host's database/sql DDL connection.
func MigrateDB(ctx context.Context, db *sql.DB, schema string) error {
	if db == nil {
		return fmt.Errorf("notify: migration database is required")
	}
	list, err := chain(schema)
	if err != nil {
		return err
	}
	return apply(ctx, migratekit.NewPostgres(db, app), schema, list)
}

func apply(ctx context.Context, m *migratekit.Postgres, schema string, list []migratekit.Migration) error {
	if err := m.WithSchema(schema).WithImmutableMigrations().ApplyMigrations(ctx, list); err != nil {
		return fmt.Errorf("notify: migrate schema %q: %w", schema, err)
	}
	return nil
}
