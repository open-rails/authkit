package authhttp

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// ak#286/#311: routes with no consumer were deleted outright — no alias, no
// 410. They must be absent from the route registry and answer 404 (not 401 or
// 405) on the mounted DefaultAPI surface.
func TestRemovedRoutesAreGone(t *testing.T) {
	svc := newMountTestService(t)
	h, err := MountHandler(svc, MountOptions{})
	require.NoError(t, err)

	removed := []struct{ method, spec, probe string }{
		{http.MethodPost, "/sessions/current", "/api/v1/sessions/current"},
		{http.MethodGet, "/user/metadata", "/api/v1/user/metadata"},
		{http.MethodPatch, "/user/metadata", "/api/v1/user/metadata"},
		{http.MethodDelete, "/me/groups/{persona}/{instance_slug}", "/api/v1/me/groups/repo/r1"},
		{http.MethodPost, "/applications/{slug}/rotate", "/api/v1/applications/app/rotate"},
		{http.MethodPost, "/applications/{slug}/repoint", "/api/v1/applications/app/repoint"},
		{http.MethodPost, "/admin/applications/{slug}/tier", "/api/v1/admin/applications/app/tier"},
		{http.MethodPost, "/admin/users/{user_id}/recover", "/api/v1/admin/users/00000000-0000-0000-0000-000000000000/recover"},
		{http.MethodPost, "/admin/users/{user_id}/restore", "/api/v1/admin/users/00000000-0000-0000-0000-000000000000/restore"},
	}
	registered := map[string]bool{}
	for _, spec := range svc.APIRoutes() {
		registered[spec.Method+" "+spec.Path] = true
	}
	for _, rt := range removed {
		require.False(t, registered[rt.method+" "+rt.spec], "%s %s is still registered", rt.method, rt.spec)
		rec := mountProbe(t, h, rt.method, rt.probe, nil)
		require.Equal(t, http.StatusNotFound, rec.Code, "%s %s: %s", rt.method, rt.probe, rec.Body.String())
	}
}
