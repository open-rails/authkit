package authkit

// #291 pgx-free root contract (#138): the root package and verify/ are the
// token-checking surface a verify-only service links. Neither may pull in the
// Postgres driver or any internal engine package.

import (
	"os/exec"
	"strings"
	"testing"
)

var forbiddenDepPrefixes = []string{
	"github.com/jackc/pgx",
	"github.com/open-rails/authkit/internal/",
}

func TestRootAndVerifyArePgxFree(t *testing.T) {
	var violations []string
	for _, pkg := range []string{".", "./verify"} {
		out, err := exec.Command("go", "list", "-deps", pkg).CombinedOutput()
		if err != nil {
			t.Fatalf("go list -deps %s: %v\n%s", pkg, err, out)
		}
		for _, dep := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			for _, prefix := range forbiddenDepPrefixes {
				if strings.HasPrefix(dep, prefix) {
					violations = append(violations, pkg+" -> "+dep)
				}
			}
		}
	}
	if len(violations) > 0 {
		t.Fatalf("root and verify must stay pgx-free (#291) — move the dependency into the engine:\n  %s",
			strings.Join(violations, "\n  "))
	}
}
