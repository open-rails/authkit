package authkitgin

import (
	"errors"
	"fmt"
	"go/token"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/open-rails/authkit/iam"
)

// Surface is AuthKit's HTTP surface; *authkit.Client implements it.
type Surface interface {
	Handler() http.Handler
	Routes() []iam.Route
}

type route struct{ method, path string }

// Mount registers every AuthKit route natively on router, so each appears in
// router.Routes() (GET routes also as HEAD). Call it during setup, before
// serving requests. Every route is served by the surface's one handler, which
// keeps AuthKit's authentication, JSON guards, cookies and request context.
// Conflicting routes and unsupported patterns return an error before any
// route is registered; exclude host replacements with HTTPConfig.Exclude.
func Mount(router *gin.Engine, s Surface) error {
	if router == nil {
		return errors.New("authkitgin: Mount requires a Gin engine")
	}
	if s == nil || s.Handler() == nil {
		return errors.New("authkitgin: Mount requires a configured AuthKit HTTP surface")
	}
	var routes []route
	for _, r := range s.Routes() {
		if r.Method == http.MethodHead {
			continue // registered beside its GET
		}
		method := r.Method
		converted, err := ginRoutePath(r.Path)
		if err != nil {
			return err
		}
		routes = append(routes, route{method, converted})
		if method == http.MethodGet {
			routes = append(routes, route{http.MethodHead, converted})
		}
	}
	if err := validateMountRoutes(router, routes); err != nil {
		return err
	}
	h := gin.WrapH(s.Handler())
	for _, r := range routes {
		router.Handle(r.method, r.path, h)
	}
	return nil
}

// Gin rejects incompatible wildcard branches by panicking. Replay the proposed
// tree on a scratch engine so configuration errors cannot partially mount the
// real application. Reuse Gin's own rules rather than maintaining a matcher.
func validateMountRoutes(router *gin.Engine, routes []route) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("authkitgin: incompatible route configuration: %v; exclude host replacements with HTTPConfig.Exclude", recovered)
		}
	}()
	probe := gin.New()
	probe.Use(router.Handlers...)
	placeholder := func(*gin.Context) {}
	for _, r := range router.Routes() {
		probe.Handle(r.Method, r.Path, placeholder)
	}
	for _, r := range routes {
		probe.Handle(r.method, r.path, placeholder)
	}
	return nil
}

// AuthKit uses complete named segments. Reject broader ServeMux patterns and
// Gin metacharacters rather than changing their meaning.
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
