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

// envClassifierLiterals are the dev/prod vocabulary strings. Comparing against
// them inline (==, !=, or a switch case) re-creates a divergent dev/prod
// classifier — the second half of the #231 bug class (the first is env reads).
// All dev/prod decisions must route through authcore.IsDevEnvironment; this is
// how a `env == "prod"` gate in http/server.go once let "staging" escape the
// production Redis requirement.
var envClassifierLiterals = map[string]bool{
	"prod":        true,
	"production":  true,
	"staging":     true,
	"dev":         true,
	"development": true,
	"local":       true,
}

// classifierAllowlist: the ONE place the vocabulary may be compared.
var classifierAllowlist = map[string]string{
	"internal/authcore/accessors.go": "IsDevEnvironment — THE single dev/prod classifier (#231)",
}

func TestSingleDevProdClassifier(t *testing.T) {
	fset := token.NewFileSet()
	var violations []string

	flag := func(pos token.Pos, lit string) {
		violations = append(violations, fset.Position(pos).String()+`: inline comparison against "`+lit+`"`)
	}
	// literalIn reports whether expr is a string literal in the classifier vocabulary.
	literalIn := func(e ast.Expr) (string, bool) {
		bl, ok := e.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return "", false
		}
		v := strings.Trim(bl.Value, "`\"")
		return v, envClassifierLiterals[v]
	}

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := filepath.ToSlash(path)
		if d.IsDir() {
			if rel == "cmd" || strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		if _, ok := classifierAllowlist[rel]; ok {
			return nil
		}

		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.BinaryExpr: // env == "prod" / env != "production"
				if node.Op != token.EQL && node.Op != token.NEQ {
					return true
				}
				if lit, ok := literalIn(node.X); ok {
					flag(node.Pos(), lit)
				} else if lit, ok := literalIn(node.Y); ok {
					flag(node.Pos(), lit)
				}
			case *ast.CaseClause: // switch env { case "prod", "staging": ... }
				for _, e := range node.List {
					if lit, ok := literalIn(e); ok {
						flag(e.Pos(), lit)
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if len(violations) > 0 {
		t.Fatalf("inline dev/prod classification (#231) — route the decision through authcore.IsDevEnvironment instead:\n  %s",
			strings.Join(violations, "\n  "))
	}
}
