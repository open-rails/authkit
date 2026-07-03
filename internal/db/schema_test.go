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
	_, _ = q.RemoteApplicationBySlug(ctx, "acme")
	_, _ = q.UserSlugAliases(ctx, "00000000-0000-0000-0000-000000000000")
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

// bareProfilesRe matches a `profiles` token NOT immediately followed by a dot —
// i.e. a schema reference that would escape RewriteSQL's `profiles.` substitution.
var bareProfilesRe = regexp.MustCompile(`\bprofiles\b([^.]|$)`)

// lineEscapesRewrite reports whether a source line contains a bare/quoted
// `profiles` schema reference that RewriteSQL would miss. Pure comment lines are
// skipped: the word "profiles" legitimately appears in prose (Go `//`, SQL `--`,
// block-comment `*` continuations) and is not executed SQL.
func lineEscapesRewrite(line string) bool {
	t := strings.TrimSpace(line)
	if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "--") || strings.HasPrefix(t, "*") {
		return false
	}
	return bareProfilesRe.MatchString(line)
}

// scanSchemaRefs reports any non-comment line under dir (files matching suffixes,
// excluding _test.go) that references the schema without a dot qualifier.
func scanSchemaRefs(t *testing.T, dir string, suffixes ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasSuffix(name, "_test.go") {
			continue
		}
		match := false
		for _, s := range suffixes {
			if strings.HasSuffix(name, s) {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if lineEscapesRewrite(line) {
				t.Errorf("%s/%s:%d: schema referenced without dot qualifier (escapes RewriteSQL): %s", dir, name, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// TestAllSQLSchemaReferencesAreDotQualified guards the rewrite contract:
// RewriteSQL only replaces the "profiles." prefix, so every reference to the
// schema must be written exactly as `profiles.<object>`. A bare or quoted
// reference (e.g. table_schema = 'profiles') would silently escape the rewrite.
// Covers BOTH this package's sqlc sources/generated constants AND the hand-written
// raw SQL in internal/authcore (permission-group store, api-keys, invite-links,
// the AdminListUsers assembly), which is where most schema-qualified SQL now lives
// and which sqlc vet does not validate.
func TestAllSQLSchemaReferencesAreDotQualified(t *testing.T) {
	scanSchemaRefs(t, ".", ".sql.go", ".sql")
	scanSchemaRefs(t, "queries", ".sql.go", ".sql")
	scanSchemaRefs(t, filepath.Join("..", "authcore"), ".go")
}

// TestSchemaQualifierGuardCatchesBareRef is a negative self-test: it proves the
// guard actually fails on a planted bare/quoted `profiles` reference (so the scan
// above is not a silent no-op), while passing a properly dot-qualified line and
// ignoring the word in comments.
func TestSchemaQualifierGuardCatchesBareRef(t *testing.T) {
	mustFlag := []string{
		`WHERE table_schema = 'profiles'`,
		"st.q.Query(ctx, `SELECT 1 FROM profiles`)",
	}
	for _, l := range mustFlag {
		if !lineEscapesRewrite(l) {
			t.Errorf("guard should flag bare schema ref: %q", l)
		}
	}
	mustPass := []string{
		"SELECT id FROM profiles.users",
		`// the profiles schema is the historical default`,
		`-- profiles is rewritten at execution time`,
	}
	for _, l := range mustPass {
		if lineEscapesRewrite(l) {
			t.Errorf("guard should NOT flag: %q", l)
		}
	}
}
