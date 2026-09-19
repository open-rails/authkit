// Package migrations embeds AuthKit's PostgreSQL schema migrations.
//
// Hosts should apply them with migratekit, which owns migration tracking:
//
// \tmigrations, err := migratekit.LoadFromFS(migrationspostgres.FS)
// \tif err != nil { return err }
// \terr = migratekit.NewPostgres(db, "authkit").WithSchema(cfg.Schema).ApplyMigrations(ctx, migrations)
package migrations

import "embed"

//go:embed *.sql
var migrationFS embed.FS

// FS exposes AuthKit's schema-neutral embedded SQL for external runners.
// migratekit applies it with the configured target schema in search_path.
var FS = migrationFS
