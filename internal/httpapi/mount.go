package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/errmodel"
)

// Mount layout. The whole surface lives beneath one base path: the path of
// the issuer, so verifiers find JWKS at the issuer plus iam.JWKSPath.
// Beneath it, browser OIDC
// sits at OIDCPath and the JSON API at APIPath plus config.APIVersion. The
// surface is ONE handler.
const OIDCPath = "/oidc"

// Mount is the canonical HTTP handler and its route catalog. Framework adapters
// use the catalog to register native routes, delegating requests to ServeHTTP
// so AuthKit still owns path values, authentication, JSON and cookie guards.
type Mount struct {
	handler http.Handler
	routes  []iam.Route
	api     string
}

func (m *Mount) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.handler.ServeHTTP(w, r)
}

// Routes returns a copy of the configured endpoints, including JWKS and enabled
// document/OIDC routes; GET endpoints also have a HEAD entry. It never
// advertises disabled or excluded endpoints.
func (m *Mount) Routes() []iam.Route {
	if m == nil {
		return nil
	}
	return append([]iam.Route(nil), m.routes...)
}

// APIBase is the path the JSON API is served at.
func (m *Mount) APIBase() string {
	if m == nil {
		return ""
	}
	return m.api
}

// mountLayout is where one mount serves its anchors, as full paths. It rides
// the request context rather than the Service, so one Service mounted twice
// builds each mount's own URLs.
type mountLayout struct {
	api  string // JSON API anchor; "/" at the host root
	oidc string // browser OIDC anchor; "" when not mounted
	jwks string // "" when excluded
}

type mountLayoutCtxKey struct{}

func withMountLayout(next http.Handler, layout mountLayout) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), mountLayoutCtxKey{}, layout)))
	})
}

func layoutFrom(r *http.Request) mountLayout {
	layout, _ := r.Context().Value(mountLayoutCtxKey{}).(mountLayout)
	return layout
}

// NewMount builds the full AuthKit surface — JSON API, browser OIDC and JWKS
// — as ONE net/http handler plus its route catalog, as Config.HTTP declares
// it. Every route keeps the gate its RouteSpec carries; the mount adds no
// auth and removes none. Excluding a route does not alter the MFA-enrollment
// exempt set, so a shadowed enroll route stays reachable through the host's
// replacement.
func NewMount(svc *Service) (result *Mount, err error) {
	if svc == nil || svc.svc == nil {
		return nil, errors.New("authkit: NewMount requires a Service constructed by httpapi.New")
	}
	opts := svc.http
	base := opts.BasePath
	api := joinRoutePath(joinRoutePath(base, opts.APIPath), config.APIVersion)
	excluded := make(map[string]bool, len(opts.Exclude))
	for _, raw := range opts.Exclude {
		method, path, ok := strings.Cut(strings.TrimSpace(raw), " ")
		path = strings.TrimSpace(path)
		if !ok || method == "" || !strings.HasPrefix(path, "/") {
			return nil, fmt.Errorf("authkit: Exclude entry %q must be \"METHOD /path\"", raw)
		}
		excluded[strings.ToUpper(method)+" "+path] = false
	}
	skip := func(method, path string) bool {
		key := method + " " + path
		if _, ok := excluded[key]; ok {
			excluded[key] = true
			return true
		}
		return false
	}

	// http.ServeMux panics on conflicting patterns; surface that as a boot
	// error — a mount that cannot serve its declared surface must fail loudly.
	defer func() {
		if p := recover(); p != nil {
			result, err = nil, fmt.Errorf("authkit: conflicting mount patterns: %v", p)
		}
	}()

	mux := http.NewServeMux()
	result = &Mount{api: api}
	layout := mountLayout{api: api}
	register := func(pattern string, handler http.Handler, route iam.Route) {
		mux.Handle(pattern, handler)
		result.routes = append(result.routes, route)
		if route.Method == http.MethodGet {
			route.Method = http.MethodHead
			result.routes = append(result.routes, route)
		}
	}
	for _, spec := range Catalog() {
		if path := joinRoutePath(base, spec.Path); spec.Surface == SurfaceBase && !skip(spec.Method, path) {
			register(spec.Method+" "+path, svc.rateLimitedRoute(spec.Bucket, spec.serve(svc)), iam.Route{Method: spec.Method, Path: path, Group: spec.Group, Auth: spec.Auth, Permission: spec.Perm})
			layout.jwks = path
		}
	}

	// #243/ak#324: the MFA-enrollment exempt surface is anchored at THIS
	// mount's API path and matched exactly.
	apiRoutes := svc.APIRoutes(opts.Groups...)
	exempt := make([]string, 0, 8)
	for _, p := range mfaEnrollmentExemptPaths(apiRoutes) {
		exempt = append(exempt, joinRoutePath(api, p))
	}
	svc.svc.AddMFAEnrollmentExemptRoutes(exempt)

	var browserOIDC []RouteSpec
	if opts.Groups == nil || routeGroupSet(opts.Groups)(iam.RouteBrowserOIDC) {
		browserOIDC = svc.OIDCBrowserRoutes()
	}
	if len(browserOIDC) > 0 {
		layout.oidc = joinRoutePath(base, OIDCPath)
	}
	mount := func(specs []RouteSpec, anchor string, jsonAPI bool) {
		for _, spec := range specs {
			if spec.Method == "" || spec.Path == "" || spec.Handler == nil {
				continue
			}
			// Link and step-up starts redirect to this mount's browser
			// callback; without one they could never complete.
			if jsonAPI && isOIDCPath(spec.Path) && layout.oidc == "" {
				continue
			}
			route := iam.Route{Method: spec.Method, Path: joinRoutePath(anchor, spec.Path), Group: spec.Group, Auth: spec.Auth, Permission: spec.Perm}
			if skip(route.Method, route.Path) {
				continue
			}
			handler := spec.Handler
			if svc.wrap != nil {
				handler = svc.wrap(route, handler)
			}
			if jsonAPI {
				handler = svc.guardJSONAPI(handler)
			}
			register(route.Method+" "+route.Path, handler, route)
		}
	}
	mount(apiRoutes, api, true)
	mount(browserOIDC, layout.oidc, false)
	mount(svc.OAuthRoutes(opts.Groups...), base, false)
	for pattern, used := range excluded {
		if !used {
			return nil, fmt.Errorf("authkit: Exclude entry %q matches no mounted route", pattern)
		}
	}

	result.handler = withMountLayout(apiMisses(mux, api), layout)
	if opts.RefreshCookie {
		result.handler = withRefreshCookiePolicy(result.handler, refreshCookiePolicy{})
	}
	return result, nil
}

func joinRoutePath(prefix, path string) string {
	prefix = strings.TrimRight(prefix, "/")
	path = "/" + strings.Trim(path, "/")
	if path == "/" {
		path = ""
	}
	if prefix == "" && path == "" {
		return "/"
	}
	return prefix + path
}

// apiMisses answers a request beneath the API anchor that matches no route
// with the JSON envelope: 404 not_found, or 405 method_not_allowed with the
// Allow header ServeMux computed.
func apiMisses(mux *http.ServeMux, api string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, pattern := mux.Handler(r)
		if pattern != "" || (api != "/" && r.URL.Path != api && !strings.HasPrefix(r.URL.Path, api+"/")) {
			mux.ServeHTTP(w, r)
			return
		}
		probe := &statusProbe{header: http.Header{}}
		h.ServeHTTP(probe, r)
		switch probe.status {
		case http.StatusNotFound:
			fail(w, errmodel.CodeNotFound)
		case http.StatusMethodNotAllowed:
			w.Header().Set("Allow", probe.header.Get("Allow"))
			fail(w, errmodel.CodeMethodNotAllowed)
		default:
			mux.ServeHTTP(w, r)
		}
	})
}

// statusProbe records the status and headers a handler answers with.
type statusProbe struct {
	header http.Header
	status int
}

func (p *statusProbe) Header() http.Header { return p.header }
func (p *statusProbe) WriteHeader(status int) {
	if p.status == 0 {
		p.status = status
	}
}
func (p *statusProbe) Write(b []byte) (int, error) {
	p.WriteHeader(http.StatusOK)
	return len(b), nil
}
