package authhttp

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Mount anchors. JWKS and browser OIDC are root-anchored by spec/convention
// (verifiers derive the JWKS URL from the issuer; OIDC redirect URIs are
// registered with providers), while the JSON API is prefix-anchored. The
// resolution (#250): MountHandler is ONE handler mounted at the HOST ROOT —
// JWKS at JWKSPath, browser OIDC under DefaultOIDCPath, API under APIPrefix.
const (
	DefaultAPIPrefix = "/api/v1"
	DefaultOIDCPath  = "/oidc"
	JWKSPath         = "/.well-known/jwks.json"
	// DocumentsPath is the root-anchored published-document surface (#260).
	// Addressable in ExcludeRoutes as GET DocumentsPath (dropping GET+HEAD).
	DocumentsPath = "/.well-known/authkit/documents/{digest}"
)

// RouteRef identifies a route by HTTP method and prefix-neutral RouteSpec path
// (e.g. "/admin/users", NOT "/api/v1/admin/users"). JWKS is addressable as
// GET JWKSPath.
type RouteRef struct {
	Method string
	Path   string
}

// MountOptions configures the combined AuthKit surface (MountHandler).
type MountOptions struct {
	// Groups selects the mounted route groups. Nil mounts the default API
	// surface plus browser OIDC. Non-nil mounts exactly the named groups —
	// include RouteBrowserOIDC to keep the browser redirect flows.
	Groups []RouteGroup
	// APIPrefix anchors the JSON API routes. "" means DefaultAPIPrefix; "/"
	// mounts the API at root.
	APIPrefix string
	// ExcludeRoutes drops routes the host shadows with its own handlers.
	// Matched by method + prefix-neutral RouteSpec path. Exclusion does NOT
	// alter the verifier's MFA-enrollment exempt-path set — that is derived
	// from the full route registry at NewServer time, so a shadowed enroll
	// route stays reachable through the host's replacement.
	ExcludeRoutes []RouteRef
	// Wrap decorates every RouteSpec-backed handler (API + browser OIDC) at
	// mount time. JWKS is not wrapped (it carries no RouteSpec).
	Wrap func(RouteSpec, http.Handler) http.Handler
	// RefreshCookie (ak#271) delivers the rotating refresh token as an
	// HttpOnly+Secure+SameSite=Lax cookie (RefreshCookieName) instead of a JSON
	// body field, so an injected script cannot read the durable credential.
	// OFF by default: a host that leaves this false gets byte-identical
	// behaviour, refresh_token in every body as before.
	//
	// When on, every session-establishing response sets the cookie and omits
	// refresh_token from its body/fragment/postMessage payload; POST /token
	// accepts the cookie when the body carries no token (body still wins, so a
	// mid-migration client is never stranded); and DELETE /logout clears it.
	// The cookie is Path-scoped to this mount's POST /token — the only route
	// that reads a refresh token — so it never rides the SPA document or assets.
	//
	// Browser-facing by construction: the host must serve the SPA and this
	// mount on the SAME origin, or the cookie never reaches the refresh call.
	RefreshCookie bool
}

// MountHandler returns the full AuthKit surface — JSON API, browser OIDC, and
// JWKS — as ONE framework-neutral net/http handler. The host mounts it once
// (a gin host uses gin.WrapH) and rewrites nothing. Every route keeps the
// gate its RouteSpec carries; the mount adds no auth and removes none.
func MountHandler(svc *Service, opts MountOptions) (h http.Handler, err error) {
	if svc == nil || svc.svc == nil || svc.verifier == nil {
		return nil, errors.New("authkit: MountHandler requires a Service constructed by authhttp.NewServer")
	}
	apiPrefix, err := normalizeAPIPrefix(opts.APIPrefix)
	if err != nil {
		return nil, err
	}
	excluded := make(map[RouteRef]bool, len(opts.ExcludeRoutes))
	for _, ref := range opts.ExcludeRoutes {
		excluded[RouteRef{Method: strings.ToUpper(strings.TrimSpace(ref.Method)), Path: strings.TrimSpace(ref.Path)}] = true
	}

	// http.ServeMux panics on conflicting patterns; surface that as a boot
	// error — a mount that cannot serve its declared surface must fail loudly.
	defer func() {
		if p := recover(); p != nil {
			h, err = nil, fmt.Errorf("authkit: conflicting mount patterns: %v", p)
		}
	}()

	mux := http.NewServeMux()
	if !excluded[RouteRef{Method: http.MethodGet, Path: JWKSPath}] {
		mux.Handle("GET "+JWKSPath, svc.JWKSHandler())
	}
	// #260: published signed documents are root-anchored by protocol (#254 —
	// resolvers derive the URL from the issuer), like JWKS. Mounted when
	// providers are wired (WithDocuments) and the group is selected; the
	// handler itself enforces GET/HEAD and reader authorization.
	if len(svc.documentProviders) > 0 &&
		(opts.Groups == nil || routeGroupSet(opts.Groups)(RouteDocuments)) &&
		!excluded[RouteRef{Method: http.MethodGet, Path: DocumentsPath}] {
		mux.Handle(DocumentsPath, svc.documentsHandler())
	}

	// #243/ak#324: the MFA-enrollment exempt surface is anchored at THIS prefix
	// and matched exactly from here on; the constructor's suffix registration
	// only ever covered the un-mounted case.
	exempt := make([]string, 0, 8)
	for _, p := range mfaEnrollmentExemptPaths(svc.APIRoutes(opts.Groups...)) {
		exempt = append(exempt, joinRoutePath(apiPrefix, p))
	}
	svc.verifier.AddMFAEnrollmentExemptRoutes(exempt)

	mount := func(specs []RouteSpec, anchor string) {
		for _, spec := range specs {
			if spec.Method == "" || spec.Path == "" || spec.Handler == nil {
				continue
			}
			if excluded[RouteRef{Method: spec.Method, Path: spec.Path}] {
				continue
			}
			handler := spec.Handler
			if opts.Wrap != nil {
				handler = opts.Wrap(spec, handler)
			}
			mux.Handle(spec.Method+" "+joinRoutePath(anchor, spec.Path), handler)
		}
	}
	mount(svc.APIRoutes(opts.Groups...), apiPrefix)
	if opts.Groups == nil || routeGroupSet(opts.Groups)(RouteBrowserOIDC) {
		mount(svc.OIDCBrowserRoutes(), DefaultOIDCPath)
	}

	if !opts.RefreshCookie {
		return mux, nil
	}
	return withRefreshCookiePolicy(mux, refreshCookiePolicy{path: refreshCookiePath(apiPrefix)}), nil
}

// refreshCookiePath anchors the refresh cookie at the mount's POST /token, the
// only route that consumes it.
func refreshCookiePath(apiPrefix string) string {
	return strings.TrimSuffix(apiPrefix, "/") + "/token"
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
