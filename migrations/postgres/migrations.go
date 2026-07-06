// Package migrations embeds AuthKit's Postgres schema migrations.
//
// Hosts should apply them via authkitmigrate, which handles pool adaptation,
// schema rendering, and migration tracking in one call:
//
//	migrator := authkitmigrate.New(pool, &authkitmigrate.Config{Schema: cfg.Schema})
//	res, err := migrator.Migrate(ctx)
//
// The raw FS (and FSForSchema for a non-default schema) remains exported for
// external migration runners.
package migrations

import (
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"testing/fstest"
)

//go:embed *.sql
var migrationFS embed.FS

// FS exposes the embedded SQL for external runners. It targets the default
// "profiles" schema; see FSForSchema for a configurable schema.
var FS = migrationFS

// defaultSchema mirrors internal/db.DefaultSchema: the historical hard-coded
// schema name all embedded DDL is written against.
const defaultSchema = "profiles"

// schemaNameRE mirrors internal/db.ValidSchemaName: the name is spliced into
// DDL text, so it must be injection-proof by construction.
var schemaNameRE = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// schemaWordRE matches every reference to the default schema in the embedded
// DDL: qualified names (profiles.users), the CREATE SCHEMA statement, and
// quoted occurrences such as table_schema = 'profiles'. \y is not available
// in Go regexp; \b covers it because "profiles" never appears as part of a
// longer identifier in these files (guarded by migrations_test.go).
var schemaWordRE = regexp.MustCompile(`\bprofiles\b`)

// FSForSchema returns the embedded migrations rendered for the given schema:
// every reference to the default "profiles" schema in the DDL (CREATE SCHEMA,
// qualified table/function names, table_schema string literals) is replaced
// with the configured name. The schema must match ^[a-z_][a-z0-9_]*$ (max 63
// bytes). For "profiles" (or empty) it returns the embedded FS unchanged, so
// callers can pass embedded.Client.Schema() unconditionally.
//
// This is a deliberate, validated text substitution performed once at load
// time — the embedded files themselves are never modified, and the FS export
// above keeps its historical behavior.
func FSForSchema(schema string) (fs.FS, error) {
	if schema == "" || schema == defaultSchema {
		return migrationFS, nil
	}
	if len(schema) > 63 || !schemaNameRE.MatchString(schema) {
		return nil, fmt.Errorf("authkit/migrations: invalid schema %q (want lowercase identifier matching ^[a-z_][a-z0-9_]*$, max 63 bytes)", schema)
	}
	entries, err := fs.ReadDir(migrationFS, ".")
	if err != nil {
		return nil, err
	}
	rendered := fstest.MapFS{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := fs.ReadFile(migrationFS, e.Name())
		if err != nil {
			return nil, err
		}
		rendered[e.Name()] = &fstest.MapFile{
			Data: schemaWordRE.ReplaceAll(b, []byte(schema)),
		}
	}
	return rendered, nil
}
