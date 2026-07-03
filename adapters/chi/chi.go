package authkitchi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/open-rails/authkit/adapters/internal/routepath"
	"github.com/open-rails/authkit/authhttp"
)

type APIOptions struct {
	Routes    []authhttp.RouteSpec
	Groups    []authhttp.RouteGroup
	Wrap      func(authhttp.RouteSpec, http.Handler) http.Handler
	routesSet bool
}

type APIOption func(*APIOptions)

func WithRoutes(routes []authhttp.RouteSpec) APIOption {
	return func(opts *APIOptions) {
		opts.Routes = routes
		opts.routesSet = true
	}
}

func WithGroups(groups ...authhttp.RouteGroup) APIOption {
	return func(opts *APIOptions) {
		opts.Groups = append([]authhttp.RouteGroup(nil), groups...)
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
	opts := APIOptions{}
	for _, option := range options {
		if option != nil {
			option(&opts)
		}
	}
	if !opts.routesSet {
		if opts.Groups != nil {
			opts.Routes = svc.Routes().Groups(opts.Groups...)
		} else {
			opts.Routes = svc.Routes().DefaultAPI()
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
	registerRoutes(r, routepath.Clean(mountPath), svc.Routes().OIDCBrowser(), nil)
}

func RegisterJWKS(r chi.Router, svc *authhttp.Service) {
	if r == nil || svc == nil {
		return
	}
	r.Method(http.MethodGet, "/.well-known/jwks.json", svc.JWKSHandler())
}

func registerRoutes(r chi.Router, mountPath string, routes []authhttp.RouteSpec, wrap func(authhttp.RouteSpec, http.Handler) http.Handler) {
	prefix := routepath.Clean(mountPath)
	for _, route := range routes {
		if route.Method == "" || route.Path == "" || route.Handler == nil {
			continue
		}
		handler := route.Handler
		if wrap != nil {
			handler = wrap(route, handler)
		}
		paramNames := routepath.ParamNames(route.Path)
		r.Method(route.Method, routepath.Join(prefix, route.Path), http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			for _, name := range paramNames {
				req.SetPathValue(name, chi.URLParam(req, name))
			}
			handler.ServeHTTP(w, req)
		}))
	}
}
