package authkit

// #231 env doctrine guard: AuthKit is a LIBRARY — library code must not read
// ambient process environment behind the host application's back. In embedded
// mode the HOST owns the process env; env is read once, at the binary boundary
// (cmd/authkit-migrate), and flows in as explicit config. This test fails on
// any os.Getenv / os.LookupEnv / os.Environ / os.ExpandEnv outside cmd/ and
// *_test.go files.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// envReadForbidden are the os-package selectors library code must not call.
var envReadForbidden = map[string]bool{
	"Getenv":    true,
	"LookupEnv": true,
	"Environ":   true,
	"ExpandEnv": true,
}

// envReadAllowlist maps a path prefix (relative to the module root, using "/"
// separators) to the justification for permitting env reads there. Additions
// require an explicit, written justification — the default is NO env reads.
var envReadAllowlist = map[string]string{
	// Test-support DB harness: imported exclusively from _test.go files, so it
	// is compiled only into test binaries and never linked into a host app.
	"internal/testdb/": "test-only DB harness, never linked into library consumers",
}

func TestLibraryCodeReadsNoEnvironment(t *testing.T) {
	fset := token.NewFileSet()
	var violations []string

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := filepath.ToSlash(path)
		if d.IsDir() {
			// Binaries own the binary boundary; hidden dirs and testdata are not library code.
			if rel == "cmd" || strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		for prefix := range envReadAllowlist {
			if strings.HasPrefix(rel, prefix) {
				return nil
			}
		}

		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || !envReadForbidden[sel.Sel.Name] {
				return true
			}
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "os" && ident.Obj == nil {
				violations = append(violations, fset.Position(sel.Pos()).String()+": os."+sel.Sel.Name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if len(violations) > 0 {
		t.Fatalf("library code must not read process env (#231) — read it in cmd/ and pass explicit config instead:\n  %s",
			strings.Join(violations, "\n  "))
	}
}

var ephemeralDevKeysAllowlist = map[string]string{
	"embedded/constructor_keys_test.go": "tests the dev-key generator itself",
	"jwtkit/":                           "owns the generator",
}

// Tests build their signing keys explicitly (jwtkit.StaticKeySource): the dev
// generator persists a keypair under the package directory (.runtime/authkit),
// so AllowEphemeralDevKeys is not a test convenience.
func TestTestsUseExplicitSigningKeys(t *testing.T) {
	fset := token.NewFileSet()
	var violations []string

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := filepath.ToSlash(path)
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		for prefix := range ephemeralDevKeysAllowlist {
			if strings.HasPrefix(rel, prefix) {
				return nil
			}
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			kv, ok := n.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "AllowEphemeralDevKeys" {
				return true
			}
			if v, ok := kv.Value.(*ast.Ident); ok && v.Name == "true" {
				violations = append(violations, fset.Position(kv.Pos()).String())
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("tests must use explicit signing keys (jwtkit.StaticKeySource), not AllowEphemeralDevKeys (#320):\n  %s",
			strings.Join(violations, "\n  "))
	}
}
