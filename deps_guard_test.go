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

// sharedStdlibLeaves are engine-free internal packages the verify surface may
// share with the engine (ak#316: one outbound/SSRF policy). Each is pinned to
// the standard library by TestSharedLeavesAreStdlibOnly.
var sharedStdlibLeaves = map[string]bool{
	"github.com/open-rails/authkit/internal/netguard": true,
}

func listDeps(t *testing.T, pkg string) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", pkg).CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps %s: %v\n%s", pkg, err, out)
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}

func TestSharedLeavesAreStdlibOnly(t *testing.T) {
	for leaf := range sharedStdlibLeaves {
		for _, dep := range listDeps(t, leaf) {
			if first, _, _ := strings.Cut(dep, "/"); dep != leaf && strings.Contains(first, ".") {
				t.Fatalf("%s must depend only on the standard library, imports %s", leaf, dep)
			}
		}
	}
}

func TestRootAndVerifyArePgxFree(t *testing.T) {
	var violations []string
	for _, pkg := range []string{".", "./verify"} {
		for _, dep := range listDeps(t, pkg) {
			if sharedStdlibLeaves[dep] {
				continue
			}
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
