package authkit_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The verification surface and the framework adapters must stay DB-less:
// hosts that only verify tokens must not link pgx, River or the engine (#291).
var dblessPackages = []string{"./iam", "./keys", "./verify", "./adapters/gin", "./adapters/fiber"}

const rootPackage = "github.com/open-rails/authkit"

var forbiddenDepPrefixes = []string{
	"github.com/jackc/pgx",
	"github.com/riverqueue/",
	"github.com/open-rails/authkit/internal/",
}

// sharedInternal are engine-free internal packages the verification surface
// may share with the engine: one outbound/SSRF policy (ak#316), one key
// policy, the JWT mechanics, one JWKS cache, one DPoP proof verifier, the
// 2FA-enrollment route marker, the error catalog (with its wire-form
// normalizer) and the typed identifiers built from token claims.
var sharedInternal = map[string]bool{
	"github.com/open-rails/authkit/internal/netguard":   true,
	"github.com/open-rails/authkit/internal/keypolicy":  true,
	"github.com/open-rails/authkit/internal/jose":       true,
	"github.com/open-rails/authkit/internal/jwks":       true,
	"github.com/open-rails/authkit/internal/dpop":       true,
	"github.com/open-rails/authkit/internal/enrollment": true,
	"github.com/open-rails/authkit/internal/ident":      true,
	errmodelPackage: true,
	wireformPackage: true,
}

// errmodelPackage is the error catalog behind iam.Error; wireformPackage the
// stdlib-only normalizer its typed metadata goes through.
const (
	errmodelPackage = "github.com/open-rails/authkit/internal/errmodel"
	wireformPackage = "github.com/open-rails/authkit/internal/wireform"
)

// helpersAuth is helpers/auth: the neutral Identity, itself standard library
// only.
const helpersAuth = "github.com/open-rails/helpers/auth"

// stdlibOnly packages depend on nothing outside the standard library, except
// the listed packages. devicekey is linked into CLIs and machines.
var stdlibOnly = map[string][]string{
	"./devicekey":           {rootPackage + "/iam", errmodelPackage, wireformPackage, helpersAuth},
	"./iam":                 {errmodelPackage, wireformPackage, helpersAuth},
	"./internal/errmodel":   {wireformPackage},
	"./internal/wireform":   nil,
	"./internal/netguard":   nil,
	"./internal/apikey":     nil,
	"./internal/enrollment": nil,
	"./internal/keypolicy":  nil,
	"./internal/ident":      {rootPackage + "/iam", errmodelPackage, wireformPackage, helpersAuth},
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
	for pkg, allowed := range stdlibOnly {
		deps := listDeps(t, pkg)
		self := deps[len(deps)-1]
		for _, dep := range deps {
			if first, _, _ := strings.Cut(dep, "/"); dep != self && strings.Contains(first, ".") && !slices.Contains(allowed, dep) {
				t.Fatalf("%s must depend only on the standard library, imports %s", pkg, dep)
			}
		}
	}
}

func TestVerificationSurfaceIsDBLess(t *testing.T) {
	var violations []string
	for _, pkg := range dblessPackages {
		for _, dep := range listDeps(t, pkg) {
			if dep == rootPackage {
				violations = append(violations, pkg+" -> "+dep)
				continue
			}
			if sharedInternal[dep] {
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

// The root is the public API over internal/engine: nothing below it imports
// it back. Only binaries and test harnesses sit above the root.
var rootImporters = map[string]bool{
	rootPackage + "/examples/reddit":     true, // a host program, like any app
	rootPackage + "/authtest":            true, // the host test kit
	rootPackage + "/internal/testhttp":   true,
}

func TestNothingBelowRootImportsRoot(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", `{{.ImportPath}}{{range .Deps}} {{.}}{{end}}`, "./...").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	var violations []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if pkg := fields[0]; pkg != rootPackage && !rootImporters[pkg] && slices.Contains(fields[1:], rootPackage) {
			violations = append(violations, pkg)
		}
	}
	if len(violations) > 0 {
		t.Fatalf("packages below the root must not import it:\n  %s", strings.Join(violations, "\n  "))
	}
}

// Request-facing code never builds an identity from path or body fields: the
// only derivation is verify's from verified claims (verify/identity.go), and
// nothing there may name the system's identity or credential, or call a host
// operation (they take no identity).
func TestRequestSurfaceCannotBuildIdentities(t *testing.T) {
	constructors := map[string]bool{"SystemIdentity": true, "UserIdentity": true, "APIKeyIdentity": true, "ApplicationIdentity": true, "DelegatedIdentity": true}
	hostOperations := map[string]bool{"CreateUser": true, "PurgeUsers": true, "ResetAccountMFA": true, "MintAccessToken": true,
		"CreateGroup": true, "DeleteGroup": true, "PurgeGroup": true, "ApplyBootstrapManifest": true, "EnsureUserRole": true,
		"ImportUsers": true, "ImportSolanaLinks": true, "LinkProvider": true}
	derivation := filepath.Join("verify", "identity.go")
	var violations []string
	for _, root := range []string{"internal/httpapi", "verify", "adapters"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			iamName := ""
			for _, imp := range file.Imports {
				if p, _ := strconv.Unquote(imp.Path.Value); p == "github.com/open-rails/authkit/iam" {
					iamName = "iam"
					if imp.Name != nil {
						iamName = imp.Name.Name
					}
				}
			}
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel.Sel.Name == "SystemIdentity" || sel.Sel.Name == "CredentialSystem" || hostOperations[sel.Sel.Name] {
					violations = append(violations, path+": "+sel.Sel.Name)
				}
				if iamName == "" {
					return true
				}
				if x, ok := sel.X.(*ast.Ident); ok && x.Name == iamName && constructors[sel.Sel.Name] && sel.Sel.Name != "SystemIdentity" {
					if path != derivation {
						violations = append(violations, path+": iam."+sel.Sel.Name)
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(violations) > 0 {
		t.Fatalf("request-facing code must derive identities only from verified claims (verify/identity.go):\n  %s", strings.Join(violations, "\n  "))
	}
}
