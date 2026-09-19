package db

import "regexp"

// DefaultSchema is AuthKit's default PostgreSQL namespace.
const DefaultSchema = "profiles"

var schemaNameRE = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// ValidSchemaName reports whether s is a safe PostgreSQL schema identifier.
func ValidSchemaName(s string) bool {
	return len(s) <= 63 && schemaNameRE.MatchString(s)
}
