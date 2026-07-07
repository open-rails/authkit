package authhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit/embedded"
	"github.com/stretchr/testify/require"
)

func newMountTestService(t *testing.T) *Service {
	t.Helper()
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), newNoDBPool(t)), WithoutRateLimiter())
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

// TestMountPrefixNormalizationAndBoundary ports the openrails #769 table test:
// trailing slashes on MountPrefix must not corrupt dispatch, prefix matching
// must respect a "/" boundary (not just a byte prefix), paths outside the
// mount must 404 cleanly, and a missing leading slash is a boot error —
// prefix-handling bugs are auth-bypass shaped.
func TestMountPrefixNormalizationAndBoundary(t *testing.T) {
	svc := newMountTestService(t)

	cases := []struct {
		name        string
		mountPrefix string
		path        string
		wantStatus  int
	}{
		{"trailing slash prefix serves identically to canonical", "/auth/", "/auth/api/v1/auth/capabilities", http.StatusOK},
		{"double trailing slash prefix also normalizes", "/auth//", "/auth/api/v1/auth/capabilities", http.StatusOK},
		{"canonical no-trailing-slash prefix unaffected", "/auth", "/auth/api/v1/auth/capabilities", http.StatusOK},
		{"jwks rides under the mount prefix", "/auth", "/auth/.well-known/jwks.json", http.StatusOK},
		{"non-matching path 404s cleanly", "/auth", "/other/api/v1/auth/capabilities", http.StatusNotFound},
		{"prefix-boundary near-miss 404s", "/auth", "/authfoo/api/v1/auth/capabilities", http.StatusNotFound},
		{"bare prefix (no rest) 404s", "/auth", "/auth", http.StatusNotFound},
		{"empty prefix unchanged", "", "/api/v1/auth/capabilities", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := MountHandler(svc, MountOptions{MountPrefix: tc.mountPrefix})
			require.NoError(t, err)
			require.Equal(t, tc.wantStatus, mountProbe(t, h, http.MethodGet, tc.path, nil).Code)
		})
	}

	_, err := MountHandler(svc, MountOptions{MountPrefix: "auth"})
	require.ErrorContains(t, err, `must start with "/"`)
	_, err = MountHandler(svc, MountOptions{APIPrefix: "api"})
	require.ErrorContains(t, err, `must start with "/"`)
	_, err = MountHandler(svc, MountOptions{OIDCPath: "oidc"})
	require.ErrorContains(t, err, `must start with "/"`)
}

// Anchors are host-tunable: "/" mounts the API at root (the old
// RegisterAPI-at-root shape), a custom OIDCPath moves the browser flows.
func TestMountAnchors(t *testing.T) {
	svc := newMountTestService(t)

	h, err := MountHandler(svc, MountOptions{APIPrefix: "/"})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, mountProbe(t, h, http.MethodGet, "/auth/capabilities", nil).Code)
	require.Equal(t, http.StatusNotFound, mountProbe(t, h, http.MethodGet, "/api/v1/auth/capabilities", nil).Code)

	// Group selection: a Groups list without the group drops its routes.
	h, err = MountHandler(svc, MountOptions{Groups: []RouteGroup{RouteAuth}})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, mountProbe(t, h, http.MethodGet, "/api/v1/auth/capabilities", nil).Code)
	require.Equal(t, http.StatusNotFound, mountProbe(t, h, http.MethodGet, "/api/v1/me", nil).Code)
}

// The #243 invariant under a mount prefix: the verifier's MFA-enrollment
// exempt paths are derived prefix-neutral at NewServer time and compared
// POST-strip (suffix-matched), so forced-enrollment gating keeps working —
// and keeps its exemptions — when the whole surface lives under MountPrefix.
func TestMountMFAEnrollmentGateUnderPrefix(t *testing.T) {
	cfg, signer := mfaGateTestConfig(t, embedded.TwoFactorRequired)
	svc, err := NewServer(newServerClient(t, cfg, newNoDBPool(t)), WithoutRateLimiter())
	require.NoError(t, err)
	token := mintUnenrolledUserToken(t, signer, cfg)
	auth := map[string]string{"Authorization": "Bearer " + token}

	h, err := MountHandler(svc, MountOptions{MountPrefix: "/authx"})
	require.NoError(t, err)

	// Non-exempt route: the forced-enrollment gate blocks through the mount.
	rec := mountProbe(t, h, http.MethodGet, "/authx/api/v1/me", auth)
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), "2fa_enrollment_required")

	// Exempt route: the gate lets it through to the handler (which then fails
	// on the absent DB — anything but the gate's 403/404 proves passage).
	rec = mountProbe(t, h, http.MethodGet, "/authx/api/v1/user/2fa", auth)
	require.NotEqual(t, http.StatusForbidden, rec.Code)
	require.NotEqual(t, http.StatusNotFound, rec.Code)
	require.NotEqual(t, http.StatusUnauthorized, rec.Code)

	// Boundary near-miss stays outside the mount even with credentials.
	require.Equal(t, http.StatusNotFound, mountProbe(t, h, http.MethodGet, "/authxx/api/v1/user/2fa", auth).Code)
}

// Excluding a route from the mount must NOT alter the verifier's exempt-path
// derivation for the remaining routes: the exempt set comes from the full
// route registry at NewServer time, not from what a particular mount serves.
func TestMountExcludeDoesNotAlterExemptDerivation(t *testing.T) {
	cfg, signer := mfaGateTestConfig(t, embedded.TwoFactorRequired)
	svc, err := NewServer(newServerClient(t, cfg, newNoDBPool(t)), WithoutRateLimiter())
	require.NoError(t, err)
	token := mintUnenrolledUserToken(t, signer, cfg)
	auth := map[string]string{"Authorization": "Bearer " + token}

	h, err := MountHandler(svc, MountOptions{
		MountPrefix:   "/authx",
		ExcludeRoutes: []RouteRef{{Method: http.MethodGet, Path: "/user/2fa"}},
	})
	require.NoError(t, err)

	// The excluded route itself is gone from the mount (405: its POST/DELETE
	// siblings still occupy the path — spec-correct ServeMux behavior).
	require.Equal(t, http.StatusMethodNotAllowed, mountProbe(t, h, http.MethodGet, "/authx/api/v1/user/2fa", auth).Code)
	// Its sibling exempt route (same path, different method) still passes the gate.
	rec := mountProbe(t, h, http.MethodPost, "/authx/api/v1/user/2fa", auth)
	require.NotEqual(t, http.StatusForbidden, rec.Code)
	require.NotEqual(t, http.StatusNotFound, rec.Code)
	// And non-exempt routes are still gated.
	require.Equal(t, http.StatusForbidden, mountProbe(t, h, http.MethodGet, "/authx/api/v1/me", auth).Code)
}
