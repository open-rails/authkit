package migrations

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

func sqlFiles(t *testing.T, fsys fs.FS) map[string]string {
	t.Helper()
	out := map[string]string{}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(b)
	}
	return out
}

// TestEmbeddedSchemaReferencesAreRewritable guards the FSForSchema contract:
// the substitution is a word-boundary replace of "profiles", so every
// occurrence of the word in the embedded DDL must actually MEAN the schema.
// This test pins each occurrence to the shapes the renderer is designed for —
// a qualified name (profiles.users), the CREATE SCHEMA statement
// (profiles;), or the quoted information_schema literal ('profiles') — so a
// future migration that uses the word any other way (e.g. in prose inside a
// comment or a seeded string value) fails here and forces a deliberate look
// at the renderer.
func TestEmbeddedSchemaReferencesAreRewritable(t *testing.T) {
	word := regexp.MustCompile(`\bprofiles\b`)
	files := sqlFiles(t, FS)
	if len(files) == 0 {
		t.Fatal("no embedded .sql files")
	}
	total := 0
	for name, content := range files {
		for i, line := range strings.Split(content, "\n") {
			for _, loc := range word.FindAllStringIndex(line, -1) {
				total++
				next := byte(0)
				if loc[1] < len(line) {
					next = line[loc[1]]
				}
				quoted := next == '\'' && loc[0] > 0 && line[loc[0]-1] == '\''
				if next == '.' || next == ';' || quoted {
					continue
				}
				t.Errorf("%s:%d: 'profiles' used in a shape FSForSchema was not designed for: %s", name, i+1, strings.TrimSpace(line))
			}
		}
	}
	if total == 0 {
		t.Fatal("no schema references found in embedded DDL")
	}
}

func TestFSForSchemaRendersDDL(t *testing.T) {
	fsys, err := FSForSchema("openrails_auth")
	if err != nil {
		t.Fatal(err)
	}
	orig := sqlFiles(t, FS)
	rendered := sqlFiles(t, fsys)
	if len(rendered) != len(orig) {
		t.Fatalf("rendered FS has %d sql files, embedded has %d", len(rendered), len(orig))
	}
	word := regexp.MustCompile(`\bprofiles\b`)
	for name, content := range rendered {
		if word.MatchString(content) {
			t.Errorf("%s: rendered DDL still references the default schema", name)
		}
	}
	first := rendered["001_auth_schema.up.sql"]
	if first == "" {
		t.Fatal("001_auth_schema.up.sql missing from rendered FS")
	}
	for _, want := range []string{
		"CREATE SCHEMA IF NOT EXISTS openrails_auth;",
		"openrails_auth.users",
		"openrails_auth.uuid_v5(",
		"WHERE table_schema = 'openrails_auth'",
	} {
		if !strings.Contains(first, want) {
			t.Errorf("rendered 001_auth_schema.up.sql missing %q", want)
		}
	}
}

func TestFSForSchemaDefaultIsPassthrough(t *testing.T) {
	for _, schema := range []string{"", "profiles"} {
		fsys, err := FSForSchema(schema)
		if err != nil {
			t.Fatal(err)
		}
		if fsys != fs.FS(migrationFS) {
			t.Errorf("FSForSchema(%q) should return the embedded FS unchanged", schema)
		}
	}
}

func TestFSForSchemaRejectsInvalidNames(t *testing.T) {
	for _, schema := range []string{"Profiles", "1abc", "a-b", "a b", `a"b`, "a;b", strings.Repeat("a", 64)} {
		if _, err := FSForSchema(schema); err == nil {
			t.Errorf("FSForSchema(%q) should error", schema)
		}
	}
}
