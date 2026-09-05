package authhttp

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/open-rails/authkit/embedded"
	"github.com/stretchr/testify/require"
)

func newMountTestService(t *testing.T) *Service {
	t.Helper()
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), newTestPool(t)), WithoutRateLimiter())
	require.NoError(t, err)
	return srv
}

func mountProbe(t *testing.T, h http.Handler, method, path string, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	h.ServeHTTP(rec, req)
	return rec
}

// Every remaining knob through the real handler: "/" mounts the API at root,
// a trailing slash normalizes, a malformed anchor is a boot error, Groups
// drops unselected routes, and Wrap decorates every RouteSpec-backed route
// but not JWKS.
func TestMountAnchors(t *testing.T) {
	svc := newMountTestService(t)

	h, err := MountHandler(svc, MountOptions{APIPrefix: "/"})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, mountProbe(t, h, http.MethodGet, "/capabilities", nil).Code)
	require.Equal(t, http.StatusNotFound, mountProbe(t, h, http.MethodGet, "/api/v1/capabilities", nil).Code)

	h, err = MountHandler(svc, MountOptions{APIPrefix: "/auth/"})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, mountProbe(t, h, http.MethodGet, "/auth/capabilities", nil).Code)
	require.Equal(t, http.StatusOK, mountProbe(t, h, http.MethodGet, JWKSPath, nil).Code)

	_, err = MountHandler(svc, MountOptions{APIPrefix: "api"})
	require.ErrorContains(t, err, `must start with "/"`)

	// Group selection: a Groups list without the group drops its routes.
	h, err = MountHandler(svc, MountOptions{Groups: []RouteGroup{RouteAuth}})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, mountProbe(t, h, http.MethodGet, "/api/v1/capabilities", nil).Code)
	require.Equal(t, http.StatusNotFound, mountProbe(t, h, http.MethodGet, "/api/v1/me", nil).Code)

	h, err = MountHandler(svc, MountOptions{Wrap: func(spec RouteSpec, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Wrapped", string(spec.Group))
			next.ServeHTTP(w, r)
		})
	}})
	require.NoError(t, err)
	require.Equal(t, string(RouteAuth), mountProbe(t, h, http.MethodGet, "/api/v1/capabilities", nil).Header().Get("X-Wrapped"))
	require.Empty(t, mountProbe(t, h, http.MethodGet, JWKSPath, nil).Header().Get("X-Wrapped"))
}

// The #243 invariant at a custom anchor: the verifier's MFA-enrollment exempt
// paths are anchored at the mount's APIPrefix (ak#324), so forced-enrollment
// gating keeps working — and keeps its exemptions — wherever the API lives.
func TestMountMFAEnrollmentGateUnderAPIPrefix(t *testing.T) {
	cfg, signer := mfaGateTestConfig(t, embedded.TwoFactorRequired)
	svc, err := NewServer(newServerClient(t, cfg, newTestPool(t)), WithoutRateLimiter())
	require.NoError(t, err)
	token := mintUnenrolledUserToken(t, signer, cfg)
	auth := map[string]string{"Authorization": "Bearer " + token}

	h, err := MountHandler(svc, MountOptions{APIPrefix: "/authx"})
	require.NoError(t, err)

	// Non-exempt route: the forced-enrollment gate blocks through the mount.
	rec := mountProbe(t, h, http.MethodGet, "/authx/me", auth)
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), "2fa_enrollment_required")

	// Exempt route: the gate lets it through to the handler (which then fails
	// on the absent DB — anything but the gate's 403/404 proves passage).
	rec = mountProbe(t, h, http.MethodGet, "/authx/user/2fa", auth)
	require.NotEqual(t, http.StatusForbidden, rec.Code)
	require.NotEqual(t, http.StatusNotFound, rec.Code)
	require.NotEqual(t, http.StatusUnauthorized, rec.Code)

	// A near-miss anchor is outside the mount even with credentials.
	require.Equal(t, http.StatusNotFound, mountProbe(t, h, http.MethodGet, "/authxx/user/2fa", auth).Code)
}

// Excluding a route from the mount must NOT alter the verifier's exempt-path
// derivation for the remaining routes: the exempt set comes from the full
// route registry at NewServer time, not from what a particular mount serves.
func TestMountExcludeDoesNotAlterExemptDerivation(t *testing.T) {
	cfg, signer := mfaGateTestConfig(t, embedded.TwoFactorRequired)
	svc, err := NewServer(newServerClient(t, cfg, newTestPool(t)), WithoutRateLimiter())
	require.NoError(t, err)
	token := mintUnenrolledUserToken(t, signer, cfg)
	auth := map[string]string{"Authorization": "Bearer " + token}

	h, err := MountHandler(svc, MountOptions{
		ExcludeRoutes: []RouteRef{{Method: http.MethodGet, Path: "/user/2fa"}},
	})
	require.NoError(t, err)

	// The excluded route itself is gone from the mount (405: its POST/DELETE
	// siblings still occupy the path — spec-correct ServeMux behavior).
	require.Equal(t, http.StatusMethodNotAllowed, mountProbe(t, h, http.MethodGet, "/api/v1/user/2fa", auth).Code)
	// Its sibling exempt route (same path, different method) still passes the gate.
	rec := mountProbe(t, h, http.MethodPost, "/api/v1/user/2fa", auth)
	require.NotEqual(t, http.StatusForbidden, rec.Code)
	require.NotEqual(t, http.StatusNotFound, rec.Code)
	// And non-exempt routes are still gated.
	require.Equal(t, http.StatusForbidden, mountProbe(t, h, http.MethodGet, "/api/v1/me", auth).Code)
}

// muxParamRe fills ServeMux "{param}" wildcards with a literal so a pattern
// can be probed as a concrete request path.
var muxParamRe = regexp.MustCompile(`\{[^}]+\}`)

// TestMountRouteTableNeverDoublesThePrefix (#265): every RouteSpec path must be
// prefix-neutral. The capabilities spec shipped hardcoded as
// "/auth/capabilities", so a host anchoring the JSON API at "/auth" (openrails
// does exactly this) served it at /auth/auth/capabilities and the expected
// /auth/capabilities 404'd. This walks the FULL route table mounted under an
// /auth-style anchor and asserts (a) no joined pattern contains a doubled
// segment, and (b) the mux resolves anchor+path to exactly that route.
func TestMountRouteTableNeverDoublesThePrefix(t *testing.T) {
	svc := newMountTestService(t)

	h, err := MountHandler(svc, MountOptions{APIPrefix: "/auth"})
	require.NoError(t, err)
	mux, ok := h.(*http.ServeMux)
	require.True(t, ok, "MountHandler without RefreshCookie returns the bare mux")

	walk := func(specs []RouteSpec, anchor string) {
		for _, spec := range specs {
			joined := joinRoutePath(anchor, spec.Path)
			segs := strings.Split(strings.Trim(joined, "/"), "/")
			for i := 1; i < len(segs); i++ {
				require.NotEqual(t, segs[i-1], segs[i],
					"%s %s: spec path %q doubles a segment under anchor %q — not mount-relative",
					spec.Method, joined, spec.Path, anchor)
			}
			req := httptest.NewRequest(spec.Method, muxParamRe.ReplaceAllString(joined, "x"), nil)
			_, pattern := mux.Handler(req)
			require.Equal(t, spec.Method+" "+joined, pattern,
				"%s %s did not resolve to its own registration", spec.Method, joined)
		}
	}
	specs := svc.APIRoutes()
	require.NotEmpty(t, specs)
	walk(specs, "/auth")
	walk(svc.OIDCBrowserRoutes(), DefaultOIDCPath)

	// The historical bug shape must stay dead: nothing answers the doubled path.
	req := httptest.NewRequest(http.MethodGet, "/auth/auth/capabilities", nil)
	_, pattern := mux.Handler(req)
	require.Empty(t, pattern, "doubled capabilities path must not resolve")
}
