package authhttp

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	authkit "github.com/open-rails/authkit"
)

func TestErrorHelpersDoNotUseBareStringCodes(t *testing.T) {
	helpers := map[string]bool{
		"badRequest":   true,
		"unauthorized": true,
		"forbidden":    true,
		"serverErr":    true,
		"notFound":     true,
	}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) < 2 {
				return true
			}
			fn, ok := call.Fun.(*ast.Ident)
			if !ok || !helpers[fn.Name] {
				return true
			}
			if lit, ok := call.Args[1].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				t.Fatalf("%s passes bare string error code at %s", fn.Name, fset.Position(lit.Pos()))
			}
			return true
		})
	}
}

func TestHTTPErrorCodeConstantServedByAPIHandler(t *testing.T) {
	server := httptest.NewServer(newTestService(t).apiHandler())
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + "/register/availability")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	var body authkit.ErrorEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != string(authkit.CodeInvalidRequest) {
		t.Fatalf("error.code = %q, want %q", body.Error.Code, authkit.CodeInvalidRequest)
	}
	// Stripe-style envelope (#115): type + message are always populated.
	if body.Error.Type != authkit.ErrorTypeInvalidRequest {
		t.Fatalf("error.type = %q, want %q", body.Error.Type, authkit.ErrorTypeInvalidRequest)
	}
	if body.Error.Message == "" {
		t.Fatalf("error.message is empty; envelope = %+v", body.Error)
	}
}
