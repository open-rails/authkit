package authhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	core "github.com/open-rails/authkit/core"
	"github.com/stretchr/testify/require"
)

// merchantSchema is the profile under test: merchant has member-assignment +
// api-key minting, but NO custom-role creation, NO remote-apps, NO invites.
// repo has members only. Mirrors core's TestGeneratedRoutes_SurfaceMirrorsProfile.
func merchantSchema(t *testing.T) *core.GroupSchema {
	t.Helper()
	s, err := core.BuildSchema(
		core.PersonaDef{
			Name: "merchant", AllowedParents: []string{core.RootPersona},
			Routes: core.ManagementProfile{MemberAssignment: true, APIKeyMinting: true},
		},
		core.PersonaDef{
			Name: "repo", AllowedParents: []string{core.RootPersona},
			Routes: core.ManagementProfile{MemberAssignment: true},
		},
	)
	require.NoError(t, err)
	return s
}

// TestGeneratedRouteTable_GatesOnDeclaredPerm asserts every generated RouteSpec
// is gated on the schema-declared perm by wiring its handler through a recording
// authorizer stub and confirming the perm it is asked to authorize.
func TestGeneratedRouteTable_GatesOnDeclaredPerm(t *testing.T) {
	s := newTestService(t)
	routes := merchantSchema(t).GeneratedRoutes()

	for _, gr := range routes {
		gr := gr
		var gotPerm, gotPersona, gotResource string
		s.groupCanFn = func(_ *http.Request, _, persona, resourceSlug, perm string) (bool, error) {
			gotPersona, gotResource, gotPerm = persona, resourceSlug, perm
			return false, nil // deny -> 403, but we only assert the gate inputs
		}
		h := s.generatedGroupHandler(gr)

		// Drive the handler with a claims-bearing request at the concrete path.
		path := strings.NewReplacer(":resource_slug", "m1", ":user", "u9", ":role", "support").Replace(gr.Path)
		r := httptest.NewRequest(gr.Method, path, nil)
		r = withMuxParams(r, gr.Path, map[string]string{"resource_slug": "m1", "user": "u9", "role": "support"})
		r = r.WithContext(setClaims(r.Context(), Claims{UserID: "caller-1"}))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		require.Equalf(t, http.StatusForbidden, w.Code, "route %s %s should 403 when authorizer denies", gr.Method, gr.Path)
		require.Equalf(t, gr.Perm, gotPerm, "route %s %s gated on wrong perm", gr.Method, gr.Path)
		require.Equal(t, gr.Persona, gotPersona)
		require.Equal(t, "m1", gotResource)
	}
}

// TestGeneratedMembersRoute_Requires401WithoutClaims: no claims => 401, gate is
// never consulted.
func TestGeneratedMembersRoute_Requires401WithoutClaims(t *testing.T) {
	s := newTestService(t)
	called := false
	s.groupCanFn = func(_ *http.Request, _, _, _, _ string) (bool, error) { called = true; return true, nil }

	gr := core.GeneratedRoute{Persona: "merchant", Method: http.MethodPost, Path: "/merchant/:resource_slug/members", Perm: "merchant:members:manage"}
	h := s.generatedGroupHandler(gr)
	r := httptest.NewRequest(http.MethodPost, "/merchant/m1/members", strings.NewReader(`{"user_id":"u9"}`))
	r = withMuxParams(r, gr.Path, map[string]string{"resource_slug": "m1"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.False(t, called, "authorizer must not be consulted without claims")
}

// withMuxParams rebuilds the request through a one-route ServeMux so r.PathValue
// is populated exactly as it would be in production (PathValue is only set when a
// request is matched by a pattern; httptest.NewRequest alone does not set it).
func withMuxParams(r *http.Request, colonPath string, _ map[string]string) *http.Request {
	pattern := r.Method + " " + muxPath(colonPath)
	mux := http.NewServeMux()
	var matched *http.Request
	mux.HandleFunc(pattern, func(_ http.ResponseWriter, rr *http.Request) { matched = rr })
	mux.ServeHTTP(httptest.NewRecorder(), r)
	if matched != nil {
		// Preserve the caller-set context (claims/body) on the matched request.
		return matched
	}
	return r
}

// TestAllGeneratedRoutesWired asserts the generator emits NO unimplemented routes:
// every per-persona management route maps to a real operation (no opStub / 501).
func TestAllGeneratedRoutesWired(t *testing.T) {
	sch, err := core.BuildSchema(core.PersonaDef{
		Name: "org", AllowedParents: []string{core.RootPersona}, AllowCustomRoles: true,
		Routes: core.ManagementProfile{MemberAssignment: true, CustomRoleCreation: true, APIKeyMinting: true, RemoteAppRegistration: true, Invitation: true},
	})
	require.NoError(t, err)
	routes := sch.GeneratedRoutes()
	require.NotEmpty(t, routes)
	for _, gr := range routes {
		require.NotEqualf(t, opStub, classifyGeneratedRoute(gr.Method, gr.Path), "generated route %s %s is unwired (opStub/501)", gr.Method, gr.Path)
	}
}
