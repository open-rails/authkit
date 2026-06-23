package authcore

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestNoLegacyOrgTerminologyInLiveSurface(t *testing.T) {
	root := repoRoot(t)
	legacy := regexp.MustCompile(`\b(?:OrgID|OrgSlug|OrgMembership|GroupType|ResourceRef|OrgIssuers|OrgIssuer|WithOrgIssuers|NewOrgIssuers)\b|resource_ref|/orgs|profiles\.(?:orgs|org_roles|org_)|group_type_parents|allowed_parent_type|parent_type`)
	roots := []string{"authbase", "core", "http", "internal/authcore", "internal/db", "verify", "migrations/postgres"}

	for _, relRoot := range roots {
		err := filepath.WalkDir(filepath.Join(root, relRoot), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			name := d.Name()
			if strings.HasSuffix(name, "_test.go") {
				return nil
			}
			if !strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, ".sql") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if m := legacy.Find(b); m != nil {
				t.Errorf("%s contains legacy AuthKit-owned terminology %q", rel(path), m)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		next := filepath.Dir(dir)
		if next == dir {
			t.Fatal("go.mod not found")
		}
		dir = next
	}
}

func rel(path string) string {
	if wd, err := os.Getwd(); err == nil {
		if r, err := filepath.Rel(wd, path); err == nil {
			return r
		}
	}
	return path
}
