package authkit

// #231 env doctrine guard: AuthKit is a LIBRARY — library code must not read
// ambient process environment behind the host application's back. In embedded
// mode the HOST owns the process env; env is read once, at the binary boundary
// (cmd/authkit-server), and flows in as explicit config. This test fails on
// any os.Getenv / os.LookupEnv / os.Environ / os.ExpandEnv outside cmd/ and
// *_test.go files.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
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

// #266 env doctrine, third leg: every env var the BINARY reads is
// AUTHKIT_-prefixed. Unprefixed names are collision magnets in shared-env
// containers (ACTIVE_KEY_ID / PUBLIC_KEYS once shipped bare). Exceptions are
// listed with an explicit justification — the default is the prefix.
var binaryEnvNameAllowlist = map[string]string{
	"DB_URL":       "platform-conventional Postgres DSN name (both-set with DATABASE_URL refuses at boot, #266)",
	"DATABASE_URL": "platform-conventional Postgres DSN name (both-set with DB_URL refuses at boot, #266)",
}

// envNameShape matches SCREAMING_SNAKE literals (at least one underscore), the
// shape of an env-var name; short flag-ish literals ("POST", ":8080") don't match.
var envNameShape = regexp.MustCompile(`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$`)

func TestBinaryEnvNamesAreAuthkitPrefixed(t *testing.T) {
	fset := token.NewFileSet()
	var violations []string

	// envReaderCallee reports whether the called function reads env: os.Getenv /
	// os.LookupEnv, or a binary-local helper following the env* / *Env naming
	// convention (envOr, envDuration, envInt, envBool, firstEnv, ...).
	envReaderCallee := func(fun ast.Expr) bool {
		switch f := fun.(type) {
		case *ast.SelectorExpr:
			ident, ok := f.X.(*ast.Ident)
			return ok && ident.Name == "os" && envReadForbidden[f.Sel.Name]
		case *ast.Ident:
			return strings.HasPrefix(f.Name, "env") || strings.HasSuffix(f.Name, "Env")
		}
		return false
	}

	err := filepath.WalkDir("cmd", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := filepath.ToSlash(path)
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}

		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !envReaderCallee(call.Fun) {
				return true
			}
			for _, arg := range call.Args {
				bl, ok := arg.(*ast.BasicLit)
				if !ok || bl.Kind != token.STRING {
					continue
				}
				name := strings.Trim(bl.Value, "`\"")
				if !envNameShape.MatchString(name) {
					continue
				}
				if strings.HasPrefix(name, "AUTHKIT_") {
					continue
				}
				if _, ok := binaryEnvNameAllowlist[name]; ok {
					continue
				}
				violations = append(violations, fset.Position(bl.Pos()).String()+": env var "+name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if len(violations) > 0 {
		t.Fatalf("unprefixed binary env names (#266) — rename to AUTHKIT_* or allowlist with justification:\n  %s",
			strings.Join(violations, "\n  "))
	}
}

var ephemeralDevKeysAllowlist = map[string]string{
	"internal/authcore/constructor_keys_test.go": "tests the dev-key generator itself",
	"jwtkit/": "owns the generator",
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
