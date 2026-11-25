// Command criticalcheck refuses a critical scenario that cannot fail: every
// ID in critical/scenarios.json is registered by one literal t.Run whose body
// (with the package's own functions and closures it reaches) uses t.Fatal*,
// t.Error* or t.Fail*. It reads critical/ and never runs it.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	scenarioName = regexp.MustCompile(`^(AK-J\d+-C\d+)_`)
	failing      = map[string]bool{"Fatal": true, "Fatalf": true, "Error": true, "Errorf": true, "Fail": true, "FailNow": true}
)

func main() {
	problems, err := check("critical")
	if err != nil {
		fmt.Fprintln(os.Stderr, "criticalcheck:", err)
		os.Exit(2)
	}
	if len(problems) > 0 {
		fmt.Fprintln(os.Stderr, strings.Join(problems, "\n"))
		os.Exit(1)
	}
}

type listed struct {
	ImportPath, Dir, Export, ForTest string
	TestGoFiles, XTestGoFiles        []string
}

// check reads the external test package in dir.
func check(dir string) ([]string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	out, err := exec.Command("go", "list", "-export", "-deps", "-test", "-json=ImportPath,Dir,Export,ForTest,TestGoFiles,XTestGoFiles", "./"+dir).Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("go list: %v\n%s", err, exit.Stderr)
		}
		return nil, err
	}
	exports := map[string]string{}
	var suite *listed
	for dec := json.NewDecoder(bytes.NewReader(out)); dec.More(); {
		var p listed
		if err := dec.Decode(&p); err != nil {
			return nil, err
		}
		path, _, _ := strings.Cut(p.ImportPath, " ")
		// A test variant of a dependency replaces it in the test's graph.
		if _, seen := exports[path]; !seen || p.ForTest != "" {
			exports[path] = p.Export
		}
		if p.Dir == abs && p.ForTest == "" && !strings.Contains(p.ImportPath, " ") && !strings.HasSuffix(p.ImportPath, ".test") {
			suite = &p
		}
	}
	switch {
	case suite == nil || len(suite.XTestGoFiles) == 0:
		return nil, fmt.Errorf("%s has no external test files", dir)
	case len(suite.TestGoFiles) > 0:
		return nil, fmt.Errorf("%s has in-package test files; only package %s_test is read", dir, filepath.Base(dir))
	}

	fset := token.NewFileSet()
	var files []*ast.File
	for _, name := range suite.XTestGoFiles {
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	info := &types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
	conf := types.Config{Importer: importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		if file := exports[path]; file != "" {
			return os.Open(file)
		}
		return nil, fmt.Errorf("no export data for %s", path)
	})}
	if _, err := conf.Check(suite.ImportPath+"_test", fset, files, info); err != nil {
		return nil, err
	}

	c := checker{info: info, funcs: map[types.Object][]*ast.BlockStmt{}, fails: map[*ast.BlockStmt]bool{}}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncDecl:
				if n.Body != nil {
					c.bind(n.Name, n.Body)
				}
			case *ast.AssignStmt:
				for i, rhs := range n.Rhs {
					if lit, ok := rhs.(*ast.FuncLit); ok && len(n.Lhs) == len(n.Rhs) {
						if id, ok := n.Lhs[i].(*ast.Ident); ok {
							c.bind(id, lit.Body)
						}
					}
				}
			case *ast.ValueSpec:
				for i, v := range n.Values {
					if lit, ok := v.(*ast.FuncLit); ok && len(n.Names) == len(n.Values) {
						c.bind(n.Names[i], lit.Body)
					}
				}
			}
			return true
		})
	}
	// A body fails when it uses a failing method or a body that fails.
	for changed := true; changed; {
		changed = false
		for _, bodies := range c.funcs {
			for _, body := range bodies {
				if !c.fails[body] && c.canFail(body) {
					c.fails[body], changed = true, true
				}
			}
		}
	}
	var problems []string
	registered := map[string]string{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 || !c.testing(call.Fun, "Run") {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			name, err := strconv.Unquote(lit.Value)
			m := scenarioName.FindStringSubmatch(name)
			if err != nil || m == nil {
				return true
			}
			at := fset.Position(call.Pos()).String()
			if prev, dup := registered[m[1]]; dup {
				problems = append(problems, fmt.Sprintf("%s: %s is registered again (first at %s)", at, m[1], prev))
			}
			registered[m[1]] = at
			if !c.canFail(call.Args[1]) {
				problems = append(problems, fmt.Sprintf("%s: %s can never fail: its body makes no t.Fatal, t.Error or t.Fail call, directly or through this package's functions", at, name))
			}
			return true
		})
	}

	var expected map[string]string
	if err := readJSON(filepath.Join(dir, "scenarios.json"), &expected); err != nil {
		return nil, err
	}
	for id := range expected {
		if registered[id] == "" {
			problems = append(problems, fmt.Sprintf("%s: no literal t.Run(%q) registers it", id, id+"_…"))
		}
	}
	for id, at := range registered {
		if _, ok := expected[id]; !ok {
			problems = append(problems, fmt.Sprintf("%s: %s is not in scenarios.json", at, id))
		}
	}

	sort.Strings(problems)
	return problems, nil
}

type checker struct {
	info *types.Info
	// funcs are the bodies of the package's functions and methods, and of
	// the closures assigned to its variables; fails, those that can fail.
	funcs map[types.Object][]*ast.BlockStmt
	fails map[*ast.BlockStmt]bool
}

func (c *checker) bind(id *ast.Ident, body *ast.BlockStmt) {
	obj := c.info.Defs[id]
	if obj == nil {
		obj = c.info.Uses[id]
	}
	if obj != nil {
		c.funcs[obj] = append(c.funcs[obj], body)
	}
}

// testing reports whether expr names the testing package's method name.
func (c *checker) testing(expr ast.Expr, name string) bool {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	fn, ok := c.info.Uses[sel.Sel].(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == "testing"
}

// canFail reports whether n uses a failing testing method, or a function or
// closure of this package known to fail. A use need not be a call: a helper
// passed as a value counts.
func (c *checker) canFail(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if found || !ok {
			return !found
		}
		obj := c.info.Uses[id]
		if fn, ok := obj.(*types.Func); ok {
			if fn.Pkg() != nil && fn.Pkg().Path() == "testing" && failing[fn.Name()] {
				found = true
				return false
			}
			obj = fn.Origin()
		}
		for _, body := range c.funcs[obj] {
			found = found || c.fails[body]
		}
		return !found
	})
	return found
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
