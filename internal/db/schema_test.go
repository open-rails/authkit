package db

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestValidSchemaName(t *testing.T) {
	valid := []string{"profiles", "openrails_auth", "_x", "a", "p2", strings.Repeat("a", 63)}
	for _, s := range valid {
		if !ValidSchemaName(s) {
			t.Errorf("ValidSchemaName(%q) = false, want true", s)
		}
	}
	invalid := []string{
		"", "Profiles", "1abc", "pro-files", "pro files", "pro.files",
		`pro"files`, "profiles;drop table x", "pröfiles", strings.Repeat("a", 64),
	}
	for _, s := range invalid {
		if ValidSchemaName(s) {
			t.Errorf("ValidSchemaName(%q) = true, want false", s)
		}
	}
}

func TestRewriteSQL(t *testing.T) {
	in := "SELECT u.id FROM profiles.users u JOIN profiles.platform_user_roles r ON r.user_id = u.id"
	got := RewriteSQL(in, "other_auth")
	want := "SELECT u.id FROM other_auth.users u JOIN other_auth.platform_user_roles r ON r.user_id = u.id"
	if got != want {
		t.Fatalf("RewriteSQL = %q, want %q", got, want)
	}
	if RewriteSQL(in, "profiles") != in {
		t.Fatal("RewriteSQL with default schema must be identity")
	}
	if RewriteSQL(in, "") != in {
		t.Fatal("RewriteSQL with empty schema must be identity")
	}
}

// recordingDBTX captures the SQL text passed to it.
type recordingDBTX struct{ sqls []string }

func (r *recordingDBTX) Exec(_ context.Context, sql string, _ ...interface{}) (pgconn.CommandTag, error) {
	r.sqls = append(r.sqls, sql)
	return pgconn.CommandTag{}, nil
}

func (r *recordingDBTX) Query(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
	r.sqls = append(r.sqls, sql)
	return nil, pgx.ErrNoRows
}

func (r *recordingDBTX) QueryRow(_ context.Context, sql string, _ ...interface{}) pgx.Row {
	r.sqls = append(r.sqls, sql)
	return errRow{}
}

type errRow struct{}

func (errRow) Scan(...interface{}) error { return pgx.ErrNoRows }

// TestForSchemaRewritesGeneratedQueries runs representative sqlc-generated
// queries through a ForSchema wrapper and asserts the SQL that reaches the
// driver targets the configured schema with no residual default qualifier.
func TestForSchemaRewritesGeneratedQueries(t *testing.T) {
	rec := &recordingDBTX{}
	q := New(ForSchema(rec, "other_auth"))
	ctx := context.Background()

	_, _ = q.UserByEmail(ctx, "user@example.com")
	_, _ = q.OrgBySlug(ctx, "acme")
	_, _ = q.PlatformUserPermissions(ctx, "00000000-0000-0000-0000-000000000000")
	_, _ = q.UserProviderSlugs(ctx, "00000000-0000-0000-0000-000000000000")

	if len(rec.sqls) == 0 {
		t.Fatal("no SQL recorded")
	}
	for _, sql := range rec.sqls {
		if strings.Contains(sql, "profiles.") {
			t.Errorf("rendered SQL still references profiles.: %s", sql)
		}
		if !strings.Contains(sql, "other_auth.") {
			t.Errorf("rendered SQL does not reference other_auth.: %s", sql)
		}
	}
}

// TestForSchemaDefaultIsPassthrough asserts the default schema gets the
// original DBTX back (zero-overhead default path).
func TestForSchemaDefaultIsPassthrough(t *testing.T) {
	rec := &recordingDBTX{}
	if got := ForSchema(rec, DefaultSchema); got != DBTX(rec) {
		t.Fatal("ForSchema(d, DefaultSchema) must return d unchanged")
	}
	if got := ForSchema(rec, ""); got != DBTX(rec) {
		t.Fatal("ForSchema(d, \"\") must return d unchanged")
	}
}

// TestAllSQLSchemaReferencesAreDotQualified guards the rewrite contract:
// RewriteSQL only replaces the "profiles." prefix, so every reference to the
// schema in this package's SQL (sqlc sources and generated constants) must be
// written exactly as `profiles.<object>`. A bare or quoted reference (e.g.
// table_schema = 'profiles') would silently escape the rewrite.
func TestAllSQLSchemaReferencesAreDotQualified(t *testing.T) {
	bare := regexp.MustCompile(`\bprofiles\b([^.]|$)`)
	for _, dir := range []string{".", "queries"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("ReadDir(%s): %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !(strings.HasSuffix(name, ".sql.go") || strings.HasSuffix(name, ".sql")) {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			for i, line := range strings.Split(string(b), "\n") {
				if bare.MatchString(line) {
					t.Errorf("%s/%s:%d: schema referenced without dot qualifier (escapes RewriteSQL): %s", dir, name, i+1, strings.TrimSpace(line))
				}
			}
		}
	}
}
