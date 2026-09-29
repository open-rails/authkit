package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/open-rails/authkit/iam"
)

// Mount layout. The whole surface lives beneath one base path: the path of
// the issuer, so verifiers and document resolvers find JWKS and documents at
// the issuer plus iam.JWKSPath and iam.DocumentsPath. Beneath it, browser OIDC
// sits at OIDCPath and the JSON API at APIPath. The surface is ONE handler.
const (
	DefaultAPIPath = "/api/v1"
	OIDCPath       = "/oidc"
)

// MountOptions configures the combined AuthKit surface.
type MountOptions struct {
	// Groups selects the mounted route groups. Nil mounts the default API
	// surface plus browser OIDC. Non-nil mounts exactly the named groups —
	// include RouteBrowserOIDC to keep the browser redirect flows.
	Groups []iam.RouteGroup
	// BasePath roots every route. "" derives it from the issuer's path; when
	// the issuer is a URL a set value must equal that path.
	BasePath string
	// APIPath anchors the JSON API beneath BasePath. "" means DefaultAPIPath;
	// "/" is BasePath itself.
	APIPath string
	// Exclude drops routes the host shadows with its own handlers, named as
	// "METHOD /full/path" patterns (excluding GET also drops HEAD). An entry
	// that matches no route is an error. Exclusion does NOT alter the
	// verifier's MFA-enrollment exempt set, so a shadowed enroll route stays
	// reachable through the host's replacement.
	Exclude []string
	// Wrap decorates every API and browser-OIDC handler at mount time. JWKS and
	// documents are not wrapped.
	Wrap func(iam.Route, http.Handler) http.Handler
	// RefreshCookie (ak#271) delivers the rotating refresh token as an
	// HttpOnly+Secure+SameSite=Lax cookie (iam.RefreshCookieName) instead of a
	// JSON body field, so an injected script cannot read the durable credential.
	//
	// When on, every session-establishing response sets the cookie and omits
	// refresh_token from its body/fragment/postMessage payload; POST /token
	// requires the cookie and rejects body refresh tokens; DELETE /logout clears
	// the cookie. Native mounts use body tokens and never consume cookies.
	//
	// Browser-facing by construction: the host must serve the SPA and this
	// mount on the SAME origin, or the cookie never reaches the refresh call.
	RefreshCookie bool
}

// Mount is the canonical HTTP handler and its route catalog. Framework adapters
// use the catalog to register native routes, delegating requests to ServeHTTP
// so AuthKit still owns path values, authentication, JSON and cookie guards.
type Mount struct {
	handler http.Handler
	routes  []iam.Route
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

// NewMount builds the full AuthKit surface — JSON API, browser OIDC, JWKS and
// published documents — as ONE net/http handler plus its route catalog. Every
// route keeps the gate its RouteSpec carries; the mount adds no auth and
// removes none.
func NewMount(svc *Service, opts MountOptions) (result *Mount, err error) {
	if svc == nil || svc.svc == nil || svc.verifier == nil {
		return nil, errors.New("authkit: NewMount requires a Service constructed by httpapi.New")
	}
	base, err := resolveBasePath(opts.BasePath, svc.settings.Issuer)
	if err != nil {
		return nil, err
	}
	api := DefaultAPIPath
	if strings.TrimSpace(opts.APIPath) != "" {
		if api, err = mountPath("APIPath", opts.APIPath); err != nil {
			return nil, err
		}
	}
	api = joinRoutePath(base, api)
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
	result = &Mount{}
	layout := mountLayout{api: api}
	register := func(pattern string, handler http.Handler, route iam.Route) {
		mux.Handle(pattern, handler)
		result.routes = append(result.routes, route)
		if route.Method == http.MethodGet {
			route.Method = http.MethodHead
			result.routes = append(result.routes, route)
		}
	}
	if jwks := joinRoutePath(base, iam.JWKSPath); !skip(http.MethodGet, jwks) {
		register("GET "+jwks, svc.JWKSHandler(), iam.Route{Method: http.MethodGet, Path: jwks, Group: iam.RouteAuth, Auth: iam.AuthPublic})
		layout.jwks = jwks
	}
	// #260: published signed documents sit beside JWKS (#254 — resolvers
	// derive the URL from the issuer). Mounted when readers are configured and
	// the group is selected; the handler itself enforces GET/HEAD and reader
	// authorization.
	if docs := joinRoutePath(base, iam.DocumentsPath); len(svc.settings.Documents.Readers) > 0 &&
		(opts.Groups == nil || routeGroupSet(opts.Groups)(iam.RouteDocuments)) &&
		!skip(http.MethodGet, docs) {
		register(docs, svc.documentsHandler(), iam.Route{Method: http.MethodGet, Path: docs, Group: iam.RouteDocuments, Auth: iam.AuthRequired})
	}

	// #243/ak#324: the MFA-enrollment exempt surface is anchored at THIS
	// mount's API path and matched exactly.
	apiRoutes := svc.APIRoutes(opts.Groups...)
	exempt := make([]string, 0, 8)
	for _, p := range mfaEnrollmentExemptPaths(apiRoutes) {
		exempt = append(exempt, joinRoutePath(api, p))
	}
	svc.verifier.AddMFAEnrollmentExemptRoutes(exempt)

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
			route := iam.Route{Method: spec.Method, Path: joinRoutePath(anchor, spec.Path), Group: spec.Group, Auth: spec.Auth, Permission: spec.Permission}
			if skip(route.Method, route.Path) {
				continue
			}
			handler := spec.Handler
			if opts.Wrap != nil {
				handler = opts.Wrap(route, handler)
			}
			if jsonAPI {
				handler = svc.guardJSONAPI(handler)
			}
			register(route.Method+" "+route.Path, handler, route)
		}
	}
	mount(apiRoutes, api, true)
	mount(browserOIDC, layout.oidc, false)
	for pattern, used := range excluded {
		if !used {
			return nil, fmt.Errorf("authkit: Exclude entry %q matches no mounted route", pattern)
		}
	}

	result.handler = withMountLayout(mux, layout)
	if opts.RefreshCookie {
		result.handler = withRefreshCookiePolicy(result.handler, refreshCookiePolicy{tokenPath: strings.TrimSuffix(api, "/") + "/token"})
	}
	return result, nil
}

// resolveBasePath derives the base from the issuer's path, or checks a set
// one against it: JWKS and documents are only found where the issuer says.
// A non-URL issuer has no path, so any base goes.
func resolveBasePath(configured, issuer string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(issuer))
	isURL := err == nil && u.Scheme != "" && u.Host != ""
	derived := ""
	if isURL {
		if derived, err = mountPath("Token.Issuer path", u.EscapedPath()); err != nil {
			return "", err
		}
	}
	if strings.TrimSpace(configured) == "" {
		return derived, nil
	}
	base, err := mountPath("BasePath", configured)
	if err != nil {
		return "", err
	}
	if isURL && base != derived {
		return "", fmt.Errorf("authkit: BasePath %q must equal the path of Token.Issuer %q, where verifiers and document resolvers look for JWKS and documents", configured, issuer)
	}
	return base, nil
}

// Plain segments only: framework routers read them literally, and escaped
// and unescaped forms are the same string.
var mountPathRE = regexp.MustCompile(`^(/[A-Za-z0-9_~-][A-Za-z0-9._~-]*)+$`)

// mountPath normalizes a configured path: surrounding space and trailing
// slashes are dropped, so "/" is "" (root).
func mountPath(field, p string) (string, error) {
	p = strings.TrimRight(strings.TrimSpace(p), "/")
	if p != "" && !mountPathRE.MatchString(p) {
		return "", fmt.Errorf("authkit: %s %q must be an absolute path of plain segments", field, p)
	}
	return p, nil
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
