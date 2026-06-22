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
		core.GroupTypeDef{
			Name: "merchant", AllowedParents: []string{core.RootType},
			Routes: core.ManagementProfile{MemberAssignment: true, APIKeyMinting: true},
		},
		core.GroupTypeDef{
			Name: "repo", AllowedParents: []string{core.RootType},
			Routes: core.ManagementProfile{MemberAssignment: true},
		},
	)
	require.NoError(t, err)
	return s
}

func routeTable(specs []RouteSpec) map[string]bool {
	m := make(map[string]bool, len(specs))
	for _, sp := range specs {
		m[sp.Method+" "+sp.Path] = true
	}
	return m
}

// TestGeneratedRouteTable_MirrorsSchemaProfile asserts the HTTP route TABLE the
// generator produces matches the declared schema profile: enabled capabilities
// are present (with ServeMux-style {param} paths), disabled ones are absent.
func TestGeneratedRouteTable_MirrorsSchemaProfile(t *testing.T) {
	s := newTestService(t)
	table := routeTable(generatedRouteSpecs(s, merchantSchema(t).GeneratedRoutes()))

	// Enabled: merchant members (CRUD + role-assign) present. ServeMux wildcard
	// names use underscores (':resource-id' -> '{resource_id}'); '-' is illegal
	// in a wildcard name.
	for _, want := range []string{
		"GET /merchant/{resource_id}/members",
		"POST /merchant/{resource_id}/members",
		"DELETE /merchant/{resource_id}/members/{user}",
		"PUT /merchant/{resource_id}/members/{user}/roles/{role}",
		"DELETE /merchant/{resource_id}/members/{user}/roles/{role}",
		"GET /merchant/{resource_id}/roles",     // catalog read always present
		"POST /merchant/{resource_id}/api-keys", // api-key minting on
		"POST /repo/{resource_id}/members",      // repo members on
	} {
		require.Truef(t, table[want], "expected generated route %q", want)
	}

	// Disabled => ABSENT (the 404 invariant: a disabled capability emits no route).
	for _, absent := range []string{
		"POST /merchant/{resource_id}/roles",               // custom-role creation OFF
		"POST /merchant/{resource_id}/remote-applications", // remote-apps OFF
		"POST /merchant/{resource_id}/invites",             // invites OFF
		"POST /repo/{resource_id}/api-keys",                // repo api-keys OFF
	} {
		require.Falsef(t, table[absent], "route %q should NOT be generated (capability disabled)", absent)
	}
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
		s.groupCanFn = func(_ *http.Request, _, persona, resourceID, perm string) (bool, error) {
			gotPersona, gotResource, gotPerm = persona, resourceID, perm
			return false, nil // deny -> 403, but we only assert the gate inputs
		}
		h := s.generatedGroupHandler(gr)

		// Drive the handler with a claims-bearing request at the concrete path.
		path := strings.NewReplacer(":resource-id", "m1", ":user", "u9", ":role", "support").Replace(gr.Path)
		r := httptest.NewRequest(gr.Method, path, nil)
		r = withMuxParams(r, gr.Path, map[string]string{"resource-id": "m1", "user": "u9", "role": "support"})
		r = r.WithContext(setClaims(r.Context(), Claims{UserID: "caller-1"}))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		require.Equalf(t, http.StatusForbidden, w.Code, "route %s %s should 403 when authorizer denies", gr.Method, gr.Path)
		require.Equalf(t, gr.Perm, gotPerm, "route %s %s gated on wrong perm", gr.Method, gr.Path)
		require.Equal(t, gr.Persona, gotPersona)
		require.Equal(t, "m1", gotResource)
	}
}

// TestGeneratedMembersRoute_AllowsThenStubsList: with the authorizer allowing,
// the members GET (list) responds 200 with an (empty, TODO) roster — proving the
// enabled members route exists and dispatches past the gate.
func TestGeneratedMembersRoute_ListAfterAllow(t *testing.T) {
	s := newTestService(t)
	s.groupCanFn = func(_ *http.Request, _, _, _, _ string) (bool, error) { return true, nil }

	gr := core.GeneratedRoute{Persona: "merchant", Method: http.MethodGet, Path: "/merchant/:resource-id/members", Perm: "merchant:members:read"}
	h := s.generatedGroupHandler(gr)
	r := httptest.NewRequest(http.MethodGet, "/merchant/m1/members", nil)
	r = withMuxParams(r, gr.Path, map[string]string{"resource-id": "m1"})
	r = r.WithContext(setClaims(r.Context(), Claims{UserID: "caller-1"}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"object":"list"`)
}

// TestGeneratedMembersRoute_Requires401WithoutClaims: no claims => 401, gate is
// never consulted.
func TestGeneratedMembersRoute_Requires401WithoutClaims(t *testing.T) {
	s := newTestService(t)
	called := false
	s.groupCanFn = func(_ *http.Request, _, _, _, _ string) (bool, error) { called = true; return true, nil }

	gr := core.GeneratedRoute{Persona: "merchant", Method: http.MethodPost, Path: "/merchant/:resource-id/members", Perm: "merchant:members:manage"}
	h := s.generatedGroupHandler(gr)
	r := httptest.NewRequest(http.MethodPost, "/merchant/m1/members", strings.NewReader(`{"user_id":"u9"}`))
	r = withMuxParams(r, gr.Path, map[string]string{"resource-id": "m1"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.False(t, called, "authorizer must not be consulted without claims")
}

// TestStubFamiliesReturn501: api-keys (enabled in profile) is wired only to a
// 501 stub; assert it 501s after the gate allows, confirming the deliberate stub.
func TestStubFamiliesReturn501(t *testing.T) {
	s := newTestService(t)
	s.groupCanFn = func(_ *http.Request, _, _, _, _ string) (bool, error) { return true, nil }

	gr := core.GeneratedRoute{Persona: "merchant", Method: http.MethodPost, Path: "/merchant/:resource-id/api-keys", Perm: "merchant:api-keys:manage"}
	h := s.generatedGroupHandler(gr)
	r := httptest.NewRequest(http.MethodPost, "/merchant/m1/api-keys", strings.NewReader(`{}`))
	r = withMuxParams(r, gr.Path, map[string]string{"resource-id": "m1"})
	r = r.WithContext(setClaims(r.Context(), Claims{UserID: "caller-1"}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusNotImplemented, w.Code)
	require.Contains(t, w.Body.String(), "not_implemented")
}

// TestMeGroups_EmptyList: /me/groups returns an empty list (core lacks a
// per-subject membership scan; documented TODO).
func TestMeGroups_EmptyList(t *testing.T) {
	s := newTestService(t)
	r := httptest.NewRequest(http.MethodGet, "/me/groups", nil)
	r = r.WithContext(setClaims(r.Context(), Claims{UserID: "caller-1"}))
	w := httptest.NewRecorder()
	s.handleMeGroupsGET(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"data":[]`)
}

// TestPermissionGroupRoutes_IncludedInDefaultAPI: the root-only default schema
// has member-assignment on, so the generated members routes appear in the
// default API surface and in the dedicated PermissionGroups accessor.
func TestPermissionGroupRoutes_IncludedInDefaultAPI(t *testing.T) {
	s := newTestService(t)

	// Root persona member routes (root type ships MemberAssignment: true).
	requireRoute(t, s.Routes().PermissionGroups(), http.MethodPost, "/root/{resource_id}/members")
	requireRoute(t, s.Routes().PermissionGroups(), http.MethodGet, "/me/groups")
	// And folded into the default API surface.
	requireRoute(t, s.Routes().DefaultAPI(), http.MethodPost, "/root/{resource_id}/members")
	// Group-selection still works: selecting only RouteRegister excludes them.
	requireNoRoute(t, s.APIRoutes(RouteRegister), http.MethodGet, "/me/groups")
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
