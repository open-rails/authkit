// Package retired converts databases built by the migration chain AuthKit
// v0.147.0–v0.148.x shipped (0001–0015, kept verbatim in v0.148/) to the v1
// baseline in place.
//
// The baseline builds exactly the schema that chain built, so the conversion
// runs no DDL. migratekit checks that the ledger records exactly this chain and
// that the schema is exactly what it builds, records the baseline as applied,
// and verifies the result equals a fresh baseline, all in one transaction. It
// reads the chain's SQL for both checks, which is why the files ship here.
package retired

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/open-rails/migratekit"
)

//go:embed v0.148/*.sql
var files embed.FS

// release is where a database on an earlier or unfinished chain upgrades first.
const release = "AuthKit v0.148.x"

// Chain returns the retired migrations as that release recorded them.
func Chain() []migratekit.Migration {
	names, err := fs.Glob(files, "v0.148/*.sql")
	if err != nil || len(names) == 0 {
		panic("authkit: retired migrations missing from the embedded FS")
	}
	sort.Strings(names)
	out := make([]migratekit.Migration, 0, len(names))
	for _, name := range names {
		content, err := files.ReadFile(name)
		if err != nil {
			panic(err)
		}
		out = append(out, migratekit.Migration{Name: name[len("v0.148/"):], Content: string(content)})
	}
	return out
}

// Conversion converts a database whose ledger holds the complete chain.
func Conversion() migratekit.Conversion {
	return migratekit.Conversion{
		Name:     "authkit v0.147–v0.148 chain",
		Retired:  func(string) ([]migratekit.Migration, error) { return Chain(), nil },
		Replaces: 1,
		// The baseline's schema is the chain's: nothing to change.
		SQL:      func(string) (string, error) { return "", nil },
		Fallback: release + ", the last release of that chain",
	}
}

// Check refuses a ledger no conversion takes: this chain part-way, or an older
// one. An empty ledger, the complete chain and the tree's own baseline pass.
func Check(ctx context.Context, m *migratekit.Postgres, tree []migratekit.Migration) error {
	ledger, err := m.AppliedRecords(ctx)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
		return nil // no ledger yet
	}
	if err != nil {
		return err
	}
	if len(ledger) == 0 || len(tree) == 0 {
		return nil
	}
	if rec, ok := ledger[migratekit.Prefix(tree[0].Name)]; ok && records(rec, tree[0]) {
		return nil
	}
	if complete(ledger, Chain()) {
		return nil
	}
	last := int64(0)
	for key := range ledger {
		if n, err := strconv.ParseInt(key, 10, 64); err == nil && n > last {
			last = n
		}
	}
	return fmt.Errorf("the ledger holds %d migrations of an earlier AuthKit chain (last %s); this release converts only the complete chain "+
		"%s shipped (0001–0015). Upgrade through %s, then this version. Nothing was changed",
		len(ledger), ledger[strconv.FormatInt(last, 10)].Filename, release, release)
}

func complete(ledger map[string]migratekit.AppliedRecord, chain []migratekit.Migration) bool {
	if len(ledger) != len(chain) {
		return false
	}
	for _, m := range chain {
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
