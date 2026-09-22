// Package authkithttp mounts a configured local Runtime on net/http or Chi.
package authkithttp

import (
	"fmt"
	"github.com/open-rails/authkit/embedded"
	"net/http"
)

type Bundle struct{ routes []embedded.HTTPRoute }

func Routes(runtime *embedded.Runtime) (*Bundle, error) {
	routes, err := runtime.HTTPRoutes()
	if err != nil {
		return nil, err
	}
	return &Bundle{routes: routes}, nil
}

// Mount registers the fully anchored inventory; JSON prefixes are part of the
// runtime configuration and JWKS/OIDC/document paths retain their root anchors.
func (b *Bundle) Mount(target any) error {
	if b == nil {
		return fmt.Errorf("authkithttp: route bundle is required")
	}
	switch r := target.(type) {
	case interface {
		Method(string, string, http.Handler)
	}:
		for _, route := range b.routes {
			r.Method(route.Method, route.Path, route.Handler)
		}
	case interface{ Handle(string, http.Handler) }:
		// Go's GET patterns already match HEAD. Registering synthetic wildcard HEAD
		// can conflict with overlapping static GET patterns, so use that native rule.
		gets := map[string]bool{}
		for _, route := range b.routes {
			if route.Method == http.MethodGet {
				gets[route.Path] = true
			}
		}
		for _, route := range b.routes {
			if route.Method == http.MethodHead && gets[route.Path] {
				continue
			}
			r.Handle(route.Method+" "+route.Path, route.Handler)
		}
	default:
		return fmt.Errorf("authkithttp: router must implement Handle or Method")
	}
	return nil
}
