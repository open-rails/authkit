package authkitfiber

import (
	"errors"
	"fmt"
	"go/token"
	"strings"

	"github.com/gofiber/fiber/v3"
	utilsstrings "github.com/gofiber/utils/v2/strings"
	"github.com/open-rails/authkit/authhttp"
)

// RouteNamePrefix identifies routes registered by Mount in app.GetRoutes().
const RouteNamePrefix = "authkit."

// Mount registers AuthKit's configured routes directly on app. Each route is
// visible through app.GetRoutes() and named "authkit.METHOD /path". Call Mount
// during application setup, before serving requests.
//
// The optional MountOptions selects route groups, exclusions, the API prefix,
// wrappers, and refresh-cookie policy. JWKS, documents, and browser OIDC retain
// their standard root paths. Handlers use AuthKit's canonical HTTP pipeline,
// including authentication, JSON guards, and cookie protections. Unmatched
// requests continue through Fiber's normal routing; no fallback is installed.
// Existing routes with the same method and normalized path cause an error;
// normalization honors CaseSensitive and StrictRouting. This checks exact
// paths, not overlapping wildcard patterns. Exclude a replaced AuthKit route
// with MountOptions.ExcludeRoutes before mounting. Every mounted method must
// be enabled by the app's RequestMethods configuration.
func Mount(app *fiber.App, svc *authhttp.Service, options ...authhttp.MountOptions) error {
	if app == nil {
		return errors.New("authkitfiber: Mount requires a Fiber app")
	}
	if len(options) > 1 {
		return errors.New("authkitfiber: Mount accepts at most one MountOptions")
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
	paths := make([]string, len(routes))
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
	for _, route := range app.GetRoutes(true) {
		existing[route.Method+" "+normalizePath(route.Path)] = true
	}
	// Validate every conversion before registering anything so unsupported
	// patterns cannot leave the host with a partially mounted auth surface.
	for i, route := range routes {
		if !methods[route.Method] {
			return fmt.Errorf("authkitfiber: route method %s is not enabled by Fiber's RequestMethods", route.Method)
		}
		paths[i], err = fiberRoutePath(route.Path)
		if err != nil {
			return err
		}
		if existing[route.Method+" "+normalizePath(paths[i])] {
			return fmt.Errorf("authkitfiber: route %s %s already registered; use MountOptions.ExcludeRoutes for host replacements", route.Method, paths[i])
		}
	}
	handler := httpHandler(mount)
	for i, route := range routes {
		app.Add([]string{route.Method}, paths[i], handler).
			Name(RouteNamePrefix + route.Method + " " + paths[i])
	}
	return nil
}

// fiberRoutePath translates the segment wildcards used by AuthKit's route
// registry. Reject broader ServeMux patterns rather than silently changing
// their meaning under Fiber's routing rules.
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
