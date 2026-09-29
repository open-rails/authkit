package authkitfiber

import (
	"errors"
	"fmt"
	"go/token"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v3"
	utilsstrings "github.com/gofiber/utils/v2/strings"
)

// RouteNamePrefix identifies routes registered by Mount in app.GetRoutes().
const RouteNamePrefix = "authkit."

// Surface is AuthKit's HTTP surface; *authkit.Auth implements it.
type Surface interface {
	Handler() http.Handler
	Patterns() []string
}

// Mount registers every AuthKit route natively on app, each visible through
// app.GetRoutes() and named "authkit.METHOD /path" (GET routes also as HEAD).
// Call it during setup, before serving requests. Every route is served by the
// surface's one handler, which keeps AuthKit's authentication, JSON guards and
// cookie protections. Unmatched requests continue through Fiber's routing.
// Existing routes with the same method and normalized path cause an error;
// normalization honors CaseSensitive and StrictRouting. Exclude a replaced
// AuthKit route with HTTPConfig.Exclude. Every mounted method must be enabled
// by the app's RequestMethods configuration.
func Mount(app *fiber.App, s Surface) error {
	if app == nil {
		return errors.New("authkitfiber: Mount requires a Fiber app")
	}
	if s == nil || s.Handler() == nil {
		return errors.New("authkitfiber: Mount requires a configured AuthKit HTTP surface")
	}
	type route struct{ method, path string }
	var routes []route
	for _, pattern := range s.Patterns() {
		method, p, ok := strings.Cut(pattern, " ")
		if !ok {
			return fmt.Errorf("authkitfiber: unsupported HTTP route pattern %q", pattern)
		}
		converted, err := fiberRoutePath(p)
		if err != nil {
			return err
		}
		routes = append(routes, route{method, converted})
		if method == http.MethodGet {
			routes = append(routes, route{http.MethodHead, converted})
		}
	}
	config := app.Config()
	normalizePath := func(path string) string {
		if !config.CaseSensitive {
			path = utilsstrings.ToLower(path)
		}
		if !config.StrictRouting && len(path) > 1 {
			path = strings.TrimRight(path, "/")
		}
		return path
	}
	methods := make(map[string]bool, len(config.RequestMethods))
	for _, method := range config.RequestMethods {
		methods[method] = true
	}
	existing := make(map[string]bool)
	for _, r := range app.GetRoutes(true) {
		existing[r.Method+" "+normalizePath(r.Path)] = true
	}
	// Validate everything before registering so an unsupported route cannot
	// leave the host with a partially mounted auth surface.
	for _, r := range routes {
		if !methods[r.method] {
			return fmt.Errorf("authkitfiber: route method %s is not enabled by Fiber's RequestMethods", r.method)
		}
		if existing[r.method+" "+normalizePath(r.path)] {
			return fmt.Errorf("authkitfiber: route %s %s already registered; exclude host replacements with HTTPConfig.Exclude", r.method, r.path)
		}
	}
	h := httpHandler(s.Handler())
	for _, r := range routes {
		app.Add([]string{r.method}, r.path, h).Name(RouteNamePrefix + r.method + " " + r.path)
	}
	return nil
}

// fiberRoutePath translates the segment wildcards AuthKit patterns use. Reject
// broader ServeMux patterns rather than silently changing their meaning under
// Fiber's routing rules.
func fiberRoutePath(path string) (string, error) {
	unsupported := func() (string, error) {
		return "", fmt.Errorf("authkitfiber: unsupported HTTP route pattern %q", path)
	}
	if !strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") {
		return unsupported()
	}
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			name := part[1 : len(part)-1]
			if !token.IsIdentifier(name) {
				return unsupported()
			}
			parts[i] = ":" + name
		} else if strings.ContainsAny(part, "{}:*+?<>\\%") {
			return unsupported()
		}
	}
	return strings.Join(parts, "/"), nil
}
