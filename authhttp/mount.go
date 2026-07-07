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
// resolution (#250): MountHandler is ONE handler designed to be mounted at the
// HOST ROOT — JWKS at JWKSPath, browser OIDC under OIDCPath, API under
// APIPrefix. MountPrefix shifts the WHOLE surface for hosts that live behind a
// non-stripping reverse proxy; using it moves JWKS/OIDC off spec-root too, so
// most hosts leave it empty.
const (
	DefaultAPIPrefix = "/api/v1"
	DefaultOIDCPath  = "/oidc"
	JWKSPath         = "/.well-known/jwks.json"
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
	// OIDCPath anchors the browser OIDC redirect flows. "" means
	// DefaultOIDCPath; "/" mounts them at root.
	OIDCPath string
	// MountPrefix is the host path the whole surface is mounted under (e.g.
	// "/auth" behind a non-stripping proxy). Empty means paths arrive
	// canonical. Trailing slashes are normalized; a non-empty prefix must
	// start with "/" (boot error otherwise); paths outside the mount 404.
	MountPrefix string
	// ExcludeRoutes drops routes the host shadows with its own handlers.
	// Matched by method + prefix-neutral RouteSpec path. Exclusion does NOT
	// alter the verifier's MFA-enrollment exempt-path set — that is derived
	// from the full route registry at NewServer time, so a shadowed enroll
	// route stays reachable through the host's replacement.
	ExcludeRoutes []RouteRef
	// Wrap decorates every RouteSpec-backed handler (API + browser OIDC) at
	// mount time. JWKS is not wrapped (it carries no RouteSpec).
	Wrap func(RouteSpec, http.Handler) http.Handler
}

// MountHandler returns the full AuthKit surface — JSON API, browser OIDC, and
// JWKS — as ONE framework-neutral net/http handler. The host mounts it once
// (a gin host uses gin.WrapH) and rewrites nothing. Every route keeps the
// gate its RouteSpec carries; the mount adds no auth and removes none.
func MountHandler(svc *Service, opts MountOptions) (h http.Handler, err error) {
	if svc == nil || svc.svc == nil || svc.verifier == nil {
		return nil, errors.New("authkit: MountHandler requires a Service constructed by authhttp.NewServer")
	}
	mountPrefix, err := normalizeMountPrefix(opts.MountPrefix)
	if err != nil {
		return nil, err
	}
	apiPrefix, err := normalizeAnchor("APIPrefix", opts.APIPrefix, DefaultAPIPrefix)
	if err != nil {
		return nil, err
	}
	oidcPath, err := normalizeAnchor("OIDCPath", opts.OIDCPath, DefaultOIDCPath)
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
		mount(svc.OIDCBrowserRoutes(), oidcPath)
	}

	if mountPrefix == "" {
		return mux, nil
	}
	return mountAt(mountPrefix, mux), nil
}

// normalizeMountPrefix trims trailing slashes (so "/auth/" and "/auth//" both
// mean the canonical "/auth") and requires a leading "/" when non-empty — a
// prefix silently missing its leading slash is far more likely a caller bug
// than an intentional relative mount, so it fails loudly at boot instead of
// silently 404ing every request.
func normalizeMountPrefix(prefix string) (string, error) {
	for strings.HasSuffix(prefix, "/") {
		prefix = strings.TrimSuffix(prefix, "/")
	}
	if prefix != "" && !strings.HasPrefix(prefix, "/") {
		return "", fmt.Errorf("authkit: MountPrefix %q must start with \"/\"", prefix)
	}
	return prefix, nil
}

// normalizeAnchor resolves an internal anchor (APIPrefix/OIDCPath): "" means
// the default, "/" means root, and anything else must start with "/".
func normalizeAnchor(name, anchor, def string) (string, error) {
	anchor = strings.TrimSpace(anchor)
	if anchor == "" {
		anchor = def
	}
	if !strings.HasPrefix(anchor, "/") {
		return "", fmt.Errorf("authkit: %s %q must start with \"/\"", name, anchor)
	}
	for strings.HasSuffix(anchor, "/") {
		anchor = strings.TrimSuffix(anchor, "/")
	}
	return anchor, nil // "" after trimming "/" means root
}

// mountAt strips mountPrefix and dispatches on the canonical path. The
// verifier's MFA-enrollment exempt paths (#243) are therefore compared
// POST-strip: route handlers (and the verify gates inside them) see the
// prefix-neutral anchored path ("/api/v1/user/2fa"), which the verifier's
// suffix match covers regardless of prefix. Paths outside the mount —
// including boundary near-misses like "/authx" against "/auth" — 404 cleanly
// instead of getting a garbage rewrite.
func mountAt(mountPrefix string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest, ok := stripMountPrefix(r.URL.Path, mountPrefix)
		if !ok {
			http.NotFound(w, r)
			return
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = rest
		if r2.URL.RawPath != "" {
			rawRest, ok := stripMountPrefix(r.URL.RawPath, mountPrefix)
			if !ok {
				http.NotFound(w, r)
				return
			}
			r2.URL.RawPath = rawRest
		}
		next.ServeHTTP(w, r2)
	})
}

// stripMountPrefix removes mountPrefix from path at a "/" boundary (path
// equals mountPrefix exactly, or continues with "/"). Returns ok=false when
// path is not under mountPrefix at all.
func stripMountPrefix(path, mountPrefix string) (rest string, ok bool) {
	if mountPrefix == "" {
		if path == "" {
			return "/", true
		}
		return path, true
	}
	if path == mountPrefix {
		return "/", true
	}
	if strings.HasPrefix(path, mountPrefix+"/") {
		return path[len(mountPrefix):], true
	}
	return "", false
}
