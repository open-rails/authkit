package authkit_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// sqlCallArgs are the pgx calls that carry SQL, with the SQL argument's index
// (after the context for Exec, Query and QueryRow; first for Batch.Queue).
// SendBatch and CopyFrom (-1) bypass sqlc whatever their arguments.
var sqlCallArgs = map[string]int{"Exec": 1, "Query": 1, "QueryRow": 1, "Queue": 0, "SendBatch": -1, "CopyFrom": -1}

// Outside the guard: sqlc's own package, host example programs (they own their
// tables), the browser e2e harness, and test-support packages.
func skipSQLGuardDir(path string) bool {
	switch path {
	case "internal/db", "examples", "sdk":
		return true
	}
	base := filepath.Base(path)
	return base != "." && strings.HasPrefix(base, ".") || base == "node_modules" || base == "testdata" ||
		strings.HasPrefix(path, "internal/test")
}

type inlineSQLSite struct {
	calls  int
	reason string
}

const pendingSQL = "pending #414 group "

// inlineSQL lists the functions outside internal/db that still hand SQL to
// pgx, keyed "file Func", with their call count. Static SQL belongs in
// internal/db/queries/*.sql (sqlc); only SQL built at runtime stays inline,
// with its reason here. #414 groups delete their pending entries.
var inlineSQL = map[string]inlineSQLSite{
	"authtest/authtest.go StaleSession":                               {1, "ages a session in a generated schema; identifiers cannot be bind parameters"},
	"authtest/authtest.go scratchSchema":                              {1, "DDL on a generated schema name; identifiers cannot be bind parameters"},
	"internal/engine/migration_access.go grantMigrationRuntimeAccess": {1, "GRANTs name the runtime role, schema and River objects; identifiers cannot be bind parameters"},
	"internal/engine/migrations.go Migrate":                           {1, "CREATE SCHEMA names the River schema; identifiers cannot be bind parameters"},
	"internal/engine/users_read.go Engine.ListUsers":                  {1, "filters, sort column and keyset cursor are chosen at runtime; it pages ids and loads rows with UsersByIDs"},
}

// Static SQL outside internal/db escapes sqlc's schema check and grows a
// second row mapping; this keeps new inline SQL out (#414).
func TestNoInlineSQL(t *testing.T) {
	found := map[string]int{}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		path = filepath.ToSlash(path)
		if d.IsDir() {
			if skipSQLGuardDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, decl := range file.Decls {
			name := declName(decl)
			ast.Inspect(decl, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if arg, ok := sqlCallArgs[sel.Sel.Name]; ok && len(call.Args) > arg {
					found[path+" "+name]++
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var problems []string
	for key, n := range found {
		site, ok := inlineSQL[key]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("%s: %d inline SQL call(s): move the SQL to internal/db/queries (sqlc)", key, n))
		case n != site.calls:
			problems = append(problems, fmt.Sprintf("%s: %d inline SQL calls, %d allowlisted", key, n, site.calls))
		}
	}
	for key := range inlineSQL {
		if found[key] == 0 {
			problems = append(problems, key+": allowlisted but has no inline SQL: delete the entry")
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Fatalf("SQL outside internal/db must go through sqlc; only SQL built at runtime stays inline, allowlisted with its reason:\n  %s",
			strings.Join(problems, "\n  "))
	}
}

func declName(decl ast.Decl) string {
	fn, ok := decl.(*ast.FuncDecl)
	if !ok {
		return "package"
	}
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	recv := fn.Recv.List[0].Type
	if star, ok := recv.(*ast.StarExpr); ok {
		recv = star.X
	}
	switch r := recv.(type) {
	case *ast.IndexExpr:
		recv = r.X
	case *ast.IndexListExpr:
		recv = r.X
	}
	if id, ok := recv.(*ast.Ident); ok {
		return id.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}
