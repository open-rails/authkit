package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoActiveTenantTerminologyResidue(t *testing.T) {
	root := repoRoot(t)
	checked := []string{"README.md", "core", "http", "internal"}
	for _, rel := range checked {
		path := filepath.Join(root, rel)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", rel, err)
		}
		if !info.IsDir() {
			checkTenantResidueFile(t, root, path)
			continue
		}
		err = filepath.WalkDir(path, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			switch filepath.Ext(path) {
			case ".go", ".md", ".sql":
				checkTenantResidueFile(t, root, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", rel, err)
		}
	}
}

func checkTenantResidueFile(t *testing.T, root, path string) {
	t.Helper()
	rel, err := filepath.Rel(root, path)
	if err != nil {
		t.Fatalf("rel %s: %v", path, err)
	}
	if rel == filepath.Join("core", "tenant_residue_test.go") {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	for i, line := range strings.Split(string(data), "\n") {
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "tenant") {
			continue
		}
		if rel == filepath.Join("core", "org_role_permissions_security_test.go") &&
			(strings.Contains(line, "tenant-era residue") ||
				strings.Contains(line, "!tenant:roles:manage") ||
				strings.Contains(line, "!tenant:members:manage")) {
			continue
		}
		t.Fatalf("unexpected tenant residue in %s:%d: %s", rel, i+1, line)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return wd
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			t.Fatal("go.mod not found")
		}
		wd = parent
	}
}
