package core

import (
	"context"
	"io/fs"
	"sort"
	"strings"
	"testing"

	migrations "github.com/open-rails/authkit/migrations/postgres"
)

// TestNonDefaultSchemaEndToEnd proves a host can point AuthKit at its own
// schema (authkit issue 69): it applies the FSForSchema-rendered migrations
// into a throwaway schema, runs a service configured with that schema against
// the SAME pool, and asserts the rows land there and not in "profiles".
// Skips without AUTHKIT_TEST_DATABASE_URL.
func TestNonDefaultSchemaEndToEnd(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	const schema = "authkit_schema_e2e"
	const slug = "schema-e2e-org"

	drop := func() { _, _ = pool.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE") }
	drop()
	t.Cleanup(drop)

	// Apply the rendered migrations in prefix order. pgx Exec without
	// arguments uses the simple protocol, so multi-statement files work.
	fsys, err := migrations.FSForSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatal("no rendered migrations")
	}
	for _, name := range names {
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, string(b)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}

	svc := NewService(Options{Issuer: "https://test", Schema: schema}, Keyset{}).WithPostgres(pool)
	if got := svc.Schema(); got != schema {
		t.Fatalf("Schema() = %q, want %q", got, schema)
	}

	// Make sure a same-slug row in the default schema can't mask the result.
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug) })

	org, err := svc.CreateOrg(ctx, slug)
	if err != nil {
		t.Fatalf("create org in schema %s: %v", schema, err)
	}
	if org.Slug != slug {
		t.Fatalf("unexpected org: %+v", org)
	}

	var inNew, inDefault int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+schema+".orgs WHERE slug=$1", slug).Scan(&inNew); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM profiles.orgs WHERE slug=$1", slug).Scan(&inDefault); err != nil {
		t.Fatal(err)
	}
	if inNew != 1 || inDefault != 0 {
		t.Fatalf("org row placement: %s.orgs=%d profiles.orgs=%d (want 1/0)", schema, inNew, inDefault)
	}

	// Read back through the service (exercises the sqlc query rewrite on the
	// SELECT path, including the transaction-seeded org roles).
	got, err := svc.ResolveOrgBySlug(ctx, slug)
	if err != nil {
		t.Fatalf("get org: %v", err)
	}
	if got.ID != org.ID {
		t.Fatalf("round-trip mismatch: %+v vs %+v", got, org)
	}
}
