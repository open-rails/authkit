// Package migrations embeds AuthKit's Postgres schema migrations.
//
// Run them with migratekit (github.com/open-rails/migratekit), the same way
// host applications do — name-tracked per app in public.migrations, so a
// recorded migration is never re-applied:
//
//	ms, _ := migratekit.LoadFromFS(migrations.FS)
//	m := migratekit.NewPostgres(sqlDB, "authkit")
//	_ = m.ApplyMigrations(ctx, ms)
package migrations

import "embed"

//go:embed *.sql
var migrationFS embed.FS

// FS exposes the embedded SQL for external runners.
var FS = migrationFS
