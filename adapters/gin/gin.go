package authkitgin

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	authhttp "github.com/open-rails/authkit/http"
)

type APIOptions struct {
	Routes []authhttp.RouteSpec
	Wrap   func(authhttp.RouteSpec, http.Handler) http.Handler
}

type APIOption func(*APIOptions)

func WithRoutes(routes []authhttp.RouteSpec) APIOption {
	return func(opts *APIOptions) {
		opts.Routes = routes
	}
}

func WithRouteWrapper(wrap func(authhttp.RouteSpec, http.Handler) http.Handler) APIOption {
	return func(opts *APIOptions) {
		opts.Wrap = wrap
	}
}

func RegisterAPI(r gin.IRouter, svc *authhttp.Service, options ...APIOption) {
	if r == nil || svc == nil {
		return
	}
	opts := APIOptions{Routes: svc.Routes().DefaultAPI()}
	for _, option := range options {
		if option != nil {
			option(&opts)
		}
	}
	registerRoutes(r, opts.Routes, opts.Wrap)
}

func RegisterRoutes(r gin.IRouter, routes []authhttp.RouteSpec, wrap func(authhttp.RouteSpec, http.Handler) http.Handler) {
	if r == nil {
		return
	}
	registerRoutes(r, routes, wrap)
}

func RegisterOIDC(r gin.IRouter, svc *authhttp.Service, mountPath string) {
	if r == nil || svc == nil {
		return
	}
	prefix := cleanMountPath(mountPath)
	routes := svc.Routes().OIDCBrowser()
	for i := range routes {
		routes[i].Path = joinRoutePath(prefix, routes[i].Path)
	}
	registerRoutes(r, routes, nil)
}

func RegisterJWKS(r gin.IRouter, svc *authhttp.Service) {
	if r == nil || svc == nil {
		return
	}
	r.GET("/.well-known/jwks.json", gin.WrapH(svc.JWKSHandler()))
}

func registerRoutes(r gin.IRouter, routes []authhttp.RouteSpec, wrap func(authhttp.RouteSpec, http.Handler) http.Handler) {
	for _, route := range routes {
		if route.Method == "" || route.Path == "" || route.Handler == nil {
			continue
		}
		handler := route.Handler
		if wrap != nil {
			handler = wrap(route, handler)
		}
		paramNames := routeParamNames(route.Path)
		r.Handle(route.Method, ginPath(route.Path), func(c *gin.Context) {
			for _, name := range paramNames {
				c.Request.SetPathValue(name, c.Param(name))
			}
			handler.ServeHTTP(c.Writer, c.Request)
		})
	}
}

func ginPath(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			name := strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}")
			parts[i] = ":" + name
		}
	}
	return strings.Join(parts, "/")
}

func routeParamNames(path string) []string {
	parts := strings.Split(path, "/")
	names := make([]string, 0)
	for _, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			names = append(names, strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}"))
		}
	}
	return names
}

func cleanMountPath(path string) string {
	path = "/" + strings.Trim(strings.TrimSpace(path), "/")
	if path == "/" {
		return ""
	}
	return path
}

func joinRoutePath(prefix, path string) string {
	prefix = cleanMountPath(prefix)
	path = "/" + strings.Trim(strings.TrimSpace(path), "/")
	if path == "/" {
		path = ""
	}
	if prefix == "" && path == "" {
		return "/"
	}
	return prefix + path
}
