package authkitgin

import (
	"errors"
	"fmt"
	"go/token"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/open-rails/authkit/authhttp"
)

// Mount registers AuthKit's configured routes directly on router. Each route,
// including HEAD, appears in router.Routes(). Call Mount during application
// setup, before serving requests.
//
// The optional MountOptions selects route groups, exclusions, the API prefix,
// wrappers, and refresh-cookie policy. JWKS, documents, and browser OIDC keep
// their standard root paths. Handlers use AuthKit's canonical HTTP pipeline,
// preserving authentication, JSON guards, cookies, and request context. Host
// middleware applies normally; unmatched paths and methods use Gin's routing.
//
// Conflicting routes and unsupported patterns return an error before any route
// is registered. Use MountOptions.ExcludeRoutes for host-owned replacements.
func Mount(router *gin.Engine, svc *authhttp.Service, options ...authhttp.MountOptions) error {
	if router == nil {
		return errors.New("authkitgin: Mount requires a Gin engine")
	}
	if len(options) > 1 {
		return errors.New("authkitgin: Mount accepts at most one MountOptions")
	}
	var opts authhttp.MountOptions
	if len(options) == 1 {
		opts = options[0]
	}
	mount, err := authhttp.NewMount(svc, opts)
	if err != nil {
		return err
	}
	routes := mount.Routes()
	for i := range routes {
		routes[i].Path, err = ginRoutePath(routes[i].Path)
		if err != nil {
			return err
		}
	}
	if err := validateMountRoutes(router, routes); err != nil {
		return err
	}
	handler := gin.WrapH(mount)
	for _, route := range routes {
		router.Handle(route.Method, route.Path, handler)
	}
	return nil
}

// Gin rejects incompatible wildcard branches by panicking. Replay the proposed
// tree on a scratch engine so configuration errors cannot partially mount the
// real application. Reuse Gin's own rules rather than maintaining a matcher.
func validateMountRoutes(router *gin.Engine, routes []authhttp.MountedRoute) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("authkitgin: incompatible route configuration: %v; use MountOptions.ExcludeRoutes for host replacements", recovered)
		}
	}()
	probe := gin.New()
	probe.Use(router.Handlers...)
	placeholder := func(*gin.Context) {}
	for _, route := range router.Routes() {
		probe.Handle(route.Method, route.Path, placeholder)
	}
	for _, route := range routes {
		probe.Handle(route.Method, route.Path, placeholder)
	}
	return nil
}

// AuthKit currently uses complete named segments. Reject broader ServeMux
// patterns and Gin metacharacters rather than changing their meaning.
func ginRoutePath(routePath string) (string, error) {
	unsupported := func() (string, error) {
		return "", fmt.Errorf("authkitgin: unsupported HTTP route pattern %q", routePath)
	}
	if !strings.HasPrefix(routePath, "/") || strings.HasSuffix(routePath, "/") || path.Clean(routePath) != routePath {
		return unsupported()
	}
	parts := strings.Split(routePath, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			name := part[1 : len(part)-1]
			if !token.IsIdentifier(name) {
				return unsupported()
			}
			parts[i] = ":" + name
		} else if strings.ContainsAny(part, "{}:*\\%") {
			return unsupported()
		}
	}
	return strings.Join(parts, "/"), nil
}
