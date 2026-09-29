// Package postgres embeds AuthKit's private PostgreSQL schema migrations.
//
// The public migration entry point is authkit.ApplyMigrations. Keeping this
// source under internal prevents consumers from bypassing AuthKit's runner.
package migrations

import "embed"

//go:embed *.sql
var migrationFS embed.FS

// FS is consumed by authkit.ApplyMigrations.
var FS = migrationFS
