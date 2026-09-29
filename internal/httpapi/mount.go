package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
)

// Mount anchors. JWKS and browser OIDC are root-anchored by spec/convention
// (verifiers derive the JWKS URL from the issuer; OIDC redirect URIs are
// registered with providers), while the JSON API is prefix-anchored. The
// whole surface is ONE handler mounted at the host root.
const (
	DefaultAPIPrefix = "/api/v1"
	DefaultOIDCPath  = "/oidc"
)

// MountOptions configures the combined AuthKit surface.
type MountOptions struct {
	// Groups selects the mounted route groups. Nil mounts the default API
	// surface plus browser OIDC. Non-nil mounts exactly the named groups —
	// include RouteBrowserOIDC to keep the browser redirect flows.
	Groups []iam.RouteGroup
	// APIPrefix anchors the JSON API routes. "" means DefaultAPIPrefix; "/"
	// mounts the API at root.
	APIPrefix string
	// Exclude drops routes the host shadows with its own handlers, named as
	// "METHOD /anchored/path" patterns (excluding GET also drops HEAD). An
	// entry that matches no route is an error. Exclusion does NOT alter the
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
	// The cookie is Path-scoped to this mount's POST /token — the only route
	// that reads a refresh token — so it never rides the SPA document or assets.
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

// NewMount builds the full AuthKit surface — JSON API, browser OIDC, JWKS and
// published documents — as ONE net/http handler plus its route catalog. Every
// route keeps the gate its RouteSpec carries; the mount adds no auth and
// removes none.
func NewMount(svc *Service, opts MountOptions) (result *Mount, err error) {
	if svc == nil || svc.svc == nil || svc.verifier == nil {
		return nil, errors.New("authkit: NewMount requires a Service constructed by httpapi.New")
	}
	apiPrefix, err := normalizeAPIPrefix(opts.APIPrefix)
	if err != nil {
		return nil, err
	}
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
	register := func(pattern string, handler http.Handler, route iam.Route) {
		mux.Handle(pattern, handler)
		result.routes = append(result.routes, route)
		if route.Method == http.MethodGet {
			route.Method = http.MethodHead
			result.routes = append(result.routes, route)
		}
	}
	if !skip(http.MethodGet, iam.JWKSPath) {
		register("GET "+iam.JWKSPath, svc.JWKSHandler(), iam.Route{Method: http.MethodGet, Path: iam.JWKSPath, Group: iam.RouteAuth, Auth: iam.AuthPublic})
	}
	// #260: published signed documents are root-anchored by protocol (#254 —
	// resolvers derive the URL from the issuer), like JWKS. Mounted when
	// readers are configured and the group is selected; the handler itself
	// enforces GET/HEAD and reader authorization.
	if len(svc.settings.Documents.Readers) > 0 &&
		(opts.Groups == nil || routeGroupSet(opts.Groups)(iam.RouteDocuments)) &&
		!skip(http.MethodGet, iam.DocumentsPath) {
		register(iam.DocumentsPath, svc.documentsHandler(), iam.Route{Method: http.MethodGet, Path: iam.DocumentsPath, Group: iam.RouteDocuments, Auth: iam.AuthRequired})
	}

	// #243/ak#324: the MFA-enrollment exempt surface is anchored at THIS
	// prefix and matched exactly.
	exempt := make([]string, 0, 8)
	for _, p := range mfaEnrollmentExemptPaths(svc.APIRoutes(opts.Groups...)) {
		exempt = append(exempt, joinRoutePath(apiPrefix, p))
	}
	svc.verifier.AddMFAEnrollmentExemptRoutes(exempt)

	mount := func(specs []RouteSpec, anchor string, jsonAPI bool) {
		for _, spec := range specs {
			if spec.Method == "" || spec.Path == "" || spec.Handler == nil {
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
	mount(svc.APIRoutes(opts.Groups...), apiPrefix, true)
	if opts.Groups == nil || routeGroupSet(opts.Groups)(iam.RouteBrowserOIDC) {
		mount(svc.OIDCBrowserRoutes(), DefaultOIDCPath, false)
	}
	for pattern, used := range excluded {
		if !used {
			return nil, fmt.Errorf("authkit: Exclude entry %q matches no mounted route", pattern)
		}
	}

	result.handler = mux
	if opts.RefreshCookie {
		result.handler = withRefreshCookiePolicy(mux, refreshCookiePolicy{tokenPath: strings.TrimSuffix(apiPrefix, "/") + "/token"})
	}
	return result, nil
}

// normalizeAPIPrefix resolves the API anchor: "" means DefaultAPIPrefix, "/"
// means root, and anything else must start with "/". Trailing slashes are
// dropped, so "" after trimming means root.
func normalizeAPIPrefix(prefix string) (string, error) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		prefix = DefaultAPIPrefix
	}
	if !strings.HasPrefix(prefix, "/") {
		return "", fmt.Errorf("authkit: APIPrefix %q must start with \"/\"", prefix)
	}
	return strings.TrimRight(prefix, "/"), nil
}
