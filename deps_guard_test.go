package authkit

import (
	"os/exec"
	"strings"
	"testing"
)

// The verification surface and the framework adapters must stay DB-less:
// hosts that only verify tokens must not link pgx, River or the engine (#291).
var dblessPackages = []string{"./iam", "./documents", "./jwtkit", "./verify", "./adapters/gin", "./adapters/fiber"}

const enginePackage = "github.com/open-rails/authkit"

var forbiddenDepPrefixes = []string{
	"github.com/jackc/pgx",
	"github.com/riverqueue/",
	"github.com/open-rails/authkit/internal/",
}

// sharedStdlibLeaves are engine-free internal packages the verify surface may
// share with the engine (ak#316: one outbound/SSRF policy). Each is pinned to
// the standard library by TestStdlibOnlyPackages.
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

func TestStdlibOnlyPackages(t *testing.T) {
	pkgs := []string{"./iam"}
	for leaf := range sharedStdlibLeaves {
		pkgs = append(pkgs, leaf)
	}
	for _, pkg := range pkgs {
		deps := listDeps(t, pkg)
		self := deps[len(deps)-1]
		for _, dep := range deps {
			if first, _, _ := strings.Cut(dep, "/"); dep != self && strings.Contains(first, ".") {
				t.Fatalf("%s must depend only on the standard library, imports %s", pkg, dep)
			}
		}
	}
}

func TestVerificationSurfaceIsDBLess(t *testing.T) {
	var violations []string
	for _, pkg := range dblessPackages {
		for _, dep := range listDeps(t, pkg) {
			if dep == enginePackage {
				violations = append(violations, pkg+" -> "+dep)
				continue
			}
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
		t.Fatalf("the verification surface must stay DB-less (#291) — move the dependency into the engine:\n  %s",
			strings.Join(violations, "\n  "))
	}
}
