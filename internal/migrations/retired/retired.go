// Package retired converts databases built by the migration chain AuthKit
// v0.125.0–v0.148.x shipped (0001–0015, kept verbatim in v0.148/) to the v1
// baseline in place. Every release in that range recorded a prefix of it.
//
// The baseline builds exactly the schema the whole chain built. A schema that
// stopped part-way runs the rest of the chain first, as v0.148.x would have,
// then records the baseline. migratekit checks that the ledger records exactly
// that prefix and that the schema is exactly what it builds, and commits only a
// result equal to a fresh baseline, all in one transaction. It reads the
// chain's SQL for those checks, which is why the files ship here.
package retired

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/open-rails/migratekit"
)

//go:embed v0.148/*.sql
var files embed.FS

var chain = sync.OnceValue(func() []migratekit.Migration {
	names, err := fs.Glob(files, "v0.148/*.sql")
	if err != nil || len(names) == 0 {
		panic("authkit: retired migrations missing from the embedded FS")
	}
	slices.Sort(names)
	out := make([]migratekit.Migration, 0, len(names))
	for _, name := range names {
		content, err := files.ReadFile(name)
		if err != nil {
			panic(err)
		}
		out = append(out, migratekit.Migration{Name: strings.TrimPrefix(name, "v0.148/"), Content: string(content)})
	}
	return out
})

// Chain returns the retired migrations as those releases recorded them.
func Chain() []migratekit.Migration { return slices.Clone(chain()) }

// Conversions returns the conversion the schema's ledger needs, read through
// m: the prefix of the chain it records, or the whole chain for an empty
// ledger (a schema without one converts only if it has the whole chain's
// shape). The tree's own baseline needs none. A ledger that does not start the
// chain is refused.
func Conversions(ctx context.Context, m *migratekit.Postgres, tree []migratekit.Migration) ([]migratekit.Conversion, error) {
	c := chain()
	ledger, err := m.AppliedRecords(ctx)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
		ledger, err = nil, nil // no ledger yet
	}
	switch {
	case err != nil:
		return nil, err
	case len(ledger) == 0:
		return []migratekit.Conversion{conversion(c, len(c))}, nil
	case len(tree) > 0 && baseline(ledger, tree[0]):
		return nil, nil
	case prefix(ledger, c):
		return []migratekit.Conversion{conversion(c, len(ledger))}, nil
	}
	last := int64(0)
	for key := range ledger {
		if n, err := strconv.ParseInt(key, 10, 64); err == nil && n > last {
			last = n
		}
	}
	return nil, fmt.Errorf("the ledger holds %d migrations (last %s) that do not start the chain AuthKit v0.125.0–v0.148.x shipped, "+
		"so this release cannot convert the schema. A schema from AuthKit v0.106.2–v0.124.0 upgrades through AuthKit v0.146.x first. "+
		"Nothing was changed", len(ledger), ledger[strconv.FormatInt(last, 10)].Filename)
}

// conversion converts a schema that recorded the chain's first n migrations:
// it runs the rest, then records the baseline.
func conversion(c []migratekit.Migration, n int) migratekit.Conversion {
	done, rest := c[:n], c[n:]
	return migratekit.Conversion{
		Name:     "authkit v0.125–v0.148 chain through " + done[n-1].Name,
		Retired:  func(string) ([]migratekit.Migration, error) { return done, nil },
		Replaces: 1,
		SQL:      func(schema string) (string, error) { return remaining(schema, rest), nil },
		Fallback: "AuthKit v0.148.x, the last release of that chain",
	}
}

// remaining is the rest of the chain as migratekit applied each migration:
// under the schema's search_path, in order.
func remaining(schema string, rest []migratekit.Migration) string {
	var b strings.Builder
	for _, m := range rest {
		b.WriteString("SET LOCAL search_path = " + pgx.Identifier{schema}.Sanitize() + ", public;\n")
		b.WriteString(m.Content)
		b.WriteString("\n")
	}
	return b.String()
}

// baseline reports whether the ledger records the tree's baseline.
func baseline(ledger map[string]migratekit.AppliedRecord, m migratekit.Migration) bool {
	rec, ok := ledger[migratekit.Prefix(m.Name)]
	return ok && rec.Filename == m.Name && records(rec, m)
}

// prefix reports whether the ledger records exactly the chain's first
// len(ledger) migrations.
func prefix(ledger map[string]migratekit.AppliedRecord, chain []migratekit.Migration) bool {
	if len(ledger) > len(chain) {
		return false
	}
	for _, m := range chain[:len(ledger)] {
		rec, ok := ledger[migratekit.Prefix(m.Name)]
		if !ok || rec.Filename != m.Name || !records(rec, m) {
			return false
		}
	}
	return true
}

// records reports whether a ledger row holds m's content, by either digest
// migratekit records.
func records(rec migratekit.AppliedRecord, m migratekit.Migration) bool {
	return rec.Digest == migratekit.ContentDigest(m.Content) || rec.SemanticDigest == migratekit.SemanticContentDigest(m.Content)
}
