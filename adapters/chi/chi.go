package authkitchi

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
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

func RegisterAPI(r chi.Router, svc *authhttp.Service, options ...APIOption) {
	if r == nil || svc == nil {
		return
	}
	opts := APIOptions{Routes: svc.Routes().DefaultAPI()}
	for _, option := range options {
		if option != nil {
			option(&opts)
		}
	}
	registerRoutes(r, "", opts.Routes, opts.Wrap)
}

func RegisterRoutes(r chi.Router, mountPath string, routes []authhttp.RouteSpec, wrap func(authhttp.RouteSpec, http.Handler) http.Handler) {
	if r == nil {
		return
	}
	registerRoutes(r, mountPath, routes, wrap)
}

func RegisterOIDC(r chi.Router, svc *authhttp.Service, mountPath string) {
	if r == nil || svc == nil {
		return
	}
	registerRoutes(r, cleanMountPath(mountPath), svc.Routes().OIDCBrowser(), nil)
}

func RegisterJWKS(r chi.Router, svc *authhttp.Service) {
	if r == nil || svc == nil {
		return
	}
	r.Method(http.MethodGet, "/.well-known/jwks.json", svc.JWKSHandler())
}

func registerRoutes(r chi.Router, mountPath string, routes []authhttp.RouteSpec, wrap func(authhttp.RouteSpec, http.Handler) http.Handler) {
	prefix := cleanMountPath(mountPath)
	for _, route := range routes {
		if route.Method == "" || route.Path == "" || route.Handler == nil {
			continue
		}
		handler := route.Handler
		if wrap != nil {
			handler = wrap(route, handler)
		}
		paramNames := routeParamNames(route.Path)
		r.Method(route.Method, joinRoutePath(prefix, route.Path), http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			for _, name := range paramNames {
				req.SetPathValue(name, chi.URLParam(req, name))
			}
			handler.ServeHTTP(w, req)
		}))
	}
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
