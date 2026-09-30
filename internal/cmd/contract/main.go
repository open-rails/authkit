// Command contract generates AuthKit's v1 contract files: from the route
// catalog (httpapi.Catalog) and the error catalog, api/openapi.json and
// auth-ui's generated wire types, route table and error codes and messages;
// from the covered packages, the Go API list api/go.txt. Run it with go
// generate ./internal/httpapi; TestGeneratedContractIsFresh and
// TestGoAPISurface fail when a generated file is stale.
package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/open-rails/authkit/internal/apisurface"
)

// repoRoot is the repository, relative to the working directory: go generate
// runs in internal/httpapi, the tests in internal/cmd/contract.
var repoRoot = "../.."

func main() {
	flag.StringVar(&repoRoot, "root", repoRoot, "repository root")
	flag.Parse()
	root := &repoRoot
	out, err := files()
	if err != nil {
		log.Fatal(err)
	}
	surface, err := apisurface.Load()
	if err != nil {
		log.Fatal(err)
	}
	out[apisurface.File] = surface.Text()
	for _, name := range sortedKeys(out) {
		path := filepath.Join(*root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(path, out[name], 0o644); err != nil {
			log.Fatal(err)
		}
	}
}

// generated is where each generated file lives, relative to the repository.
const (
	openAPIFile    = "api/openapi.json"
	wireTSFile     = "auth-ui/src/client/generated/wire.ts"
	routesTSFile   = "auth-ui/src/client/generated/routes.ts"
	errorCodesFile = "auth-ui/src/client/generated/error-codes.ts"
)

// files is every generated file by its repository path.
func files() (map[string][]byte, error) {
	c, err := newContract()
	if err != nil {
		return nil, err
	}
	openapi, err := c.openAPI()
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		openAPIFile:    openapi,
		wireTSFile:     c.wireTS(),
		routesTSFile:   c.routesTS(),
		errorCodesFile: errorCodesTS(),
	}, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
