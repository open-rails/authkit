// Package postgres embeds AuthKit's private PostgreSQL schema migrations.
//
// authkit.New applies them (through the engine's Migrate). Keeping this
// source under internal prevents consumers from bypassing AuthKit's runner.
package migrations

import "embed"

//go:embed *.sql
var migrationFS embed.FS

// FS is consumed by the engine's Migrate, which authkit.New runs.
var FS = migrationFS
