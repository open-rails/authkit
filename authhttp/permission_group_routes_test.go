package authhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-rails/authkit/embedded"
	"github.com/stretchr/testify/require"
)

// TestGeneratedMembersRoute_Requires401WithoutClaims: no claims => 401, gate is
// never consulted.
func TestGeneratedMembersRoute_Requires401WithoutClaims(t *testing.T) {
	s := newTestService(t)

	gr := embedded.GeneratedRoute{Persona: "merchant", Method: http.MethodPost, Path: "/merchant/:instance_slug/members", Perm: "merchant:members:manage"}
	h := s.generatedGroupHandler(gr)
	r := httptest.NewRequest(http.MethodPost, "/merchant/m1/members", strings.NewReader(`{"user_id":"u9"}`))
	r = withMuxParams(r, gr.Path, map[string]string{"instance_slug": "m1"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusUnauthorized, w.Code)
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
	sch, err := embedded.BuildSchema(embedded.PersonaDef{
		Name:         "org",
		Parent:       embedded.RootPersona,
		Capabilities: embedded.PersonaCapabilities{CustomRoles: true, APIKeys: true, RemoteApplications: true},
	})
	require.NoError(t, err)
	routes := sch.GeneratedRoutes()
	require.NotEmpty(t, routes)
	for _, gr := range routes {
		require.NotEqualf(t, opStub, classifyGeneratedRoute(gr.Method, gr.Path), "generated route %s %s is unwired (opStub/501)", gr.Method, gr.Path)
	}
}
