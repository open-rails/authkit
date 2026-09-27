// Package retired holds AuthKit's retired PostgreSQL chains and the verified
// conversions that bring databases built by them to the current baseline.
//
// The v0.125.0 baseline folded v0.124.0's recoverable account deletion into a
// fresh 0001. Databases created by v0.106.2–v0.124.0 recorded the older 0001
// (and, for v0.124.0, its 0002). migratekit converts them only when both the
// ledger and the schema's shape prove which chain built them, and commits only
// a result equal to a fresh current 0001.
package retired

import (
	"embed"

	"github.com/open-rails/migratekit"
)

//go:embed *.sql
var files embed.FS

// File returns one retired migration or conversion file.
func File(name string) migratekit.Migration {
	content, err := files.ReadFile(name)
	if err != nil {
		panic("authkit: retired migration " + name + " missing from the embedded FS")
	}
	return migratekit.Migration{Name: name, Content: string(content)}
}

func chain(names ...string) migratekit.Render {
	return func(string) ([]migratekit.Migration, error) {
		out := make([]migratekit.Migration, 0, len(names))
		for _, name := range names {
			out = append(out, File(name))
		}
		return out, nil
	}
}

func sqlOf(name string) func(string) (string, error) {
	return func(string) (string, error) { return File(name).Content, nil }
}

// Conversions returns every retired chain AuthKit converts from. AuthKit's
// migrations are schema-relative, so each chain renders the same for any schema.
func Conversions() []migratekit.Conversion {
	return []migratekit.Conversion{
		{
			Name:     "authkit v0.106.2–v0.123.0 baseline",
			Retired:  chain("0001_schema.up.sql"),
			Replaces: 1,
			SQL:      sqlOf("convert_from_v0106.sql"),
			Fallback: "AuthKit v0.124.0 once with River composed (it moves in-flight deletions into recoverable deletion and schedules them), then this release",
		},
		{
			Name:     "authkit v0.124.0 recoverable deletion",
			Retired:  chain("0001_schema.up.sql", "0002_recoverable_account_deletion.up.sql"),
			Replaces: 1,
			SQL:      sqlOf("convert_from_v0124.sql"),
			Fallback: "AuthKit v0.124.0 with River composed until every deletion is scheduled, then this release",
		},
	}
}
