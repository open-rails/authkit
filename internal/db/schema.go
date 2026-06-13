// Schema indirection (authkit issue 69).
//
// Every SQL statement in authkit — the sqlc-generated constants in this
// package and the few raw statements in core — is schema-qualified with the
// literal prefix "profiles.". Hosts embed authkit with a pgx pool that is
// SHARED with their own queries, so pointing authkit at a different schema via
// search_path on the pool is ruled out (it would leak into host queries).
// Instead the qualifier stays in the SQL text and becomes a variable: ForSchema
// wraps a DBTX so the "profiles." prefix is rewritten to "<schema>." on every
// statement at execution time. This is a deliberate, documented string
// substitution: schema names are validated against a strict identifier
// grammar (ValidSchemaName) at configuration time, every authkit table/function
// reference is written as `profiles.<name>` (guarded by a test in this
// package), and the rewrite is the identity (no wrapper at all) for the
// default schema, so existing embedders see zero change.
package db

import (
	"context"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DefaultSchema is the historical hard-coded schema name. All SQL in this
// package is written against it; ForSchema rewrites it when a host configures
// a different schema.
const DefaultSchema = "profiles"

// schemaNameRE is the strict identifier grammar accepted for configured schema
// names. Deliberately narrower than Postgres (no uppercase, no quoting): the
// name is spliced into SQL text, so it must be injection-proof by construction.
var schemaNameRE = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// ValidSchemaName reports whether s is acceptable as a configured schema name:
// lowercase snake_case identifier, at most 63 bytes (the Postgres identifier
// limit, so the name is never silently truncated server-side).
func ValidSchemaName(s string) bool {
	return len(s) <= 63 && schemaNameRE.MatchString(s)
}

// RewriteSQL returns sql with every literal "profiles." qualifier replaced by
// schema+".". Callers must have validated schema via ValidSchemaName.
func RewriteSQL(sql, schema string) string {
	if schema == DefaultSchema || schema == "" {
		return sql
	}
	return strings.ReplaceAll(sql, DefaultSchema+".", schema+".")
}

// ForSchema wraps d so every statement executed through it has its
// "profiles." qualifiers rewritten to the given schema. For the default
// schema (or empty, meaning default) it returns d unchanged, so the default
// path has zero overhead. The per-call strings.ReplaceAll is negligible next
// to the network round trip and keeps the wrapper stateless, which matters
// because transaction-scoped wrappers are created per transaction.
func ForSchema(d DBTX, schema string) DBTX {
	if schema == DefaultSchema || schema == "" {
		return d
	}
	return &schemaDBTX{d: d, schema: schema}
}

type schemaDBTX struct {
	d      DBTX
	schema string
}

func (w *schemaDBTX) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	return w.d.Exec(ctx, RewriteSQL(sql, w.schema), args...)
}

func (w *schemaDBTX) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return w.d.Query(ctx, RewriteSQL(sql, w.schema), args...)
}

func (w *schemaDBTX) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	return w.d.QueryRow(ctx, RewriteSQL(sql, w.schema), args...)
}
