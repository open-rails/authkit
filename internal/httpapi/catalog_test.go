package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/cursor"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/ident"
)

// The conventions the v1 contract freezes, checked on the route catalog
// itself. Real responses are checked against the same catalog by the
// integration suites (internal/apitest's conformance check).

func apiRoutes() []httpapi.RouteSpec {
	var out []httpapi.RouteSpec
	for _, r := range httpapi.Catalog() {
		if r.Surface == httpapi.SurfaceAPI {
			out = append(out, r)
		}
	}
	return out
}

// Status table: 200 is a result, 201 a creation (with a secret shown once),
// 202 accepted or sent, 204 done; 202 and 204 carry no body. A GET answers
// 200, an idempotent DELETE 204.
func TestCatalogStatusTable(t *testing.T) {
	for _, r := range apiRoutes() {
		route := r.Method + " " + r.Path
		require.NotEmpty(t, r.Responses, "%s declares no success", route)
		seen := map[int]bool{}
		for _, reply := range r.Responses {
			require.False(t, seen[reply.Status], "%s declares %d twice", route, reply.Status)
			seen[reply.Status] = true
			switch reply.Status {
			case http.StatusOK, http.StatusCreated:
				require.NotNil(t, reply.Body, "%s: %d answers a body", route, reply.Status)
			case http.StatusAccepted, http.StatusNoContent:
				require.Nil(t, reply.Body, "%s: %d answers no body", route, reply.Status)
			default:
				t.Errorf("%s: success status %d is not in the status table", route, reply.Status)
			}
		}
		switch r.Method {
		case http.MethodGet:
			require.Equal(t, []int{http.StatusOK}, statuses(r), route)
		case http.MethodDelete:
			require.Equal(t, []int{http.StatusNoContent}, statuses(r), route)
		}
		if seen[http.StatusCreated] {
			require.Contains(t, []string{http.MethodPost}, r.Method, "%s: only a POST creates", route)
		}
	}
}

func statuses(r httpapi.RouteSpec) []int {
	var out []int
	for _, reply := range r.Responses {
		out = append(out, reply.Status)
	}
	return out
}

// Null policy: every response member is always present (no omitempty); an
// unset value is null, so it is a pointer; times are time.Time, durations
// integer *_seconds; a list is the one envelope, iam.ListPage.
func TestCatalogResponseShapes(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var walk func(t reflect.Type, path string)
	walk = func(typ reflect.Type, path string) {
		if seen[typ] {
			return
		}
		seen[typ] = true
		switch httpapi.KindOf(typ) {
		case httpapi.WireNullable, httpapi.WireArray, httpapi.WireMap:
			walk(typ.Elem(), path)
		case httpapi.WirePage:
			walk(httpapi.PageItem(typ), path)
		case httpapi.WireNumber:
			t.Errorf("%s: %s is a float; the wire has integers", path, typ)
		case httpapi.WireObject:
			for _, f := range httpapi.Fields(typ) {
				at := path + "." + typ.Name() + "." + f.Name
				require.NotContains(t, f.Tag, "omitempty", "%s: every member is always present", at)
				require.NotContains(t, f.Tag, "omitzero", "%s: every member is always present", at)
				require.NotContains(t, []string{"object", "data", "next_cursor"}, f.Name, "%s: lists are iam.ListPage", at)
				base := f.Type
				if base.Kind() == reflect.Pointer {
					base = base.Elem()
				}
				if strings.HasSuffix(f.Name, "_at") {
					require.Equal(t, reflect.TypeFor[time.Time](), base, "%s: a time is a time.Time", at)
				}
				if strings.HasSuffix(f.Name, "_seconds") {
					require.Equal(t, httpapi.WireInteger, httpapi.KindOf(base), "%s: a duration is integer seconds", at)
				}
				walk(f.Type, path)
			}
		}
	}
	for _, r := range apiRoutes() {
		for _, reply := range r.Responses {
			if reply.Body != nil {
				body := reflect.TypeOf(reply.Body)
				require.NotEqual(t, reflect.Slice, body.Kind(), "%s %s: a list answers iam.ListPage, not a bare array", r.Method, r.Path)
				walk(body, r.Method+" "+r.Path)
			}
		}
	}
}

// Every route is unique, and declares its gate: a permission route names its
// permission, and a root permission is a real one.
func TestCatalogDeclaresGates(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range httpapi.Catalog() {
		key := string(r.Surface) + " " + r.Method + " " + r.Path
		require.False(t, seen[key], "%s twice", key)
		seen[key] = true
		require.NotEmpty(t, r.Group, key)
		require.NotEmpty(t, r.Auth, key)
		if r.Auth == iam.AuthPermission {
			require.NotEmpty(t, r.Perm, "%s: a permission route names its permission", key)
		}
		if strings.HasPrefix(r.Perm, "root:") {
			require.True(t, slices.Contains(append(ident.IntrinsicRootPermissions(), ident.MembersRead(iam.RootPersona()), ident.MembersManage(iam.RootPersona())), ident.Perm(r.Perm)), "%s: %s", key, r.Perm)
		}
		require.Contains(t, append(httpapi.Features, httpapi.Always), r.MountedWhen, key)
		// A signed-in change checks the session (AuthSession) or runs through
		// the actor's session binding (AuthPermission); only logout, which
		// must end an already revoked session too, is AuthRequired.
		if r.Method != http.MethodGet && r.Auth == iam.AuthRequired {
			require.Equal(t, "DELETE /logout", r.Method+" "+r.Path, "%s changes state: declare AuthSession or AuthPermission", key)
		}
		if r.StepUp {
			require.Contains(t, []iam.RouteAuthTier{iam.AuthSession, iam.AuthPermission}, r.Auth, "%s: a step-up follows the session check", key)
		}
	}
}

// Every route spends a per-address bucket, and every bucket has a default.
func TestCatalogRateLimitsEveryRoute(t *testing.T) {
	defaults := httpapi.DefaultRateLimits()
	for _, r := range httpapi.Catalog() {
		key := string(r.Surface) + " " + r.Method + " " + r.Path
		require.NotEmpty(t, r.Bucket, "%s has no rate-limit bucket", key)
		require.Contains(t, defaults, r.Bucket, key)
	}
	require.NotContains(t, defaults, httpapi.RLGlobal, "the global limit is HTTPConfig.GlobalRateLimit, not a bucket")
}

// One page parser: limit 1-500, default 50, anything else 400 on param limit.
func TestPageQuery(t *testing.T) {
	limit := func(n int) *int { return &n }
	for _, bad := range []int{0, -1, iam.MaxPageLimit + 1} {
		_, err := httpapi.PageQuery{Limit: limit(bad)}.Page()
		require.Equal(t, "limit", errmodel.As(err).Param(), "limit=%d", bad)
		require.Equal(t, errmodel.CodeInvalidRequest.String(), errmodel.As(err).Code())
	}
	page, err := httpapi.PageQuery{Cursor: "c"}.Page()
	require.NoError(t, err)
	require.Equal(t, iam.PageRequest{Cursor: "c"}, page)
	require.Equal(t, iam.DefaultPageLimit, page.PageLimit())
	for _, ok := range []int{1, iam.MaxPageLimit} {
		page, err := httpapi.PageQuery{Limit: limit(ok)}.Page()
		require.NoError(t, err)
		require.Equal(t, ok, page.PageLimit())
	}
}

// One cursor codec: opaque base64url; anything this deployment did not issue
// is 400 on param cursor.
func TestCursorCodec(t *testing.T) {
	c := cursor.Encode([]string{"a", "b"})
	require.NotContains(t, c, "a")
	keys, err := cursor.Keys(c, 2)
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, keys)
	first, err := cursor.Keys("", 2)
	require.NoError(t, err)
	require.Equal(t, []string{"", ""}, first)
	for _, bad := range []string{"not base64!", cursor.Encode([]string{"a"}), cursor.Encode([]string{"", "b"}), cursor.Encode(map[string]int{"x": 1})} {
		_, err := cursor.Keys(bad, 2)
		require.Equal(t, "cursor", errmodel.As(err).Param(), bad)
	}
}

// The error envelope always has its five members, and a server failure says
// only internal_error.
func TestErrorEnvelope(t *testing.T) {
	for _, err := range []error{errmodel.E(errmodel.CodeForbidden), errmodel.E(errmodel.CodeInvalidEmail), errmodel.Internal("op", nil)} {
		w := httptest.NewRecorder()
		iam.WriteError(w, err)
		var body map[string]map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		require.ElementsMatch(t, []string{"type", "code", "message", "param", "metadata"}, keys(body["error"]))
		require.Equal(t, "application/json", w.Header().Get("Content-Type"))
	}
}

func keys(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
