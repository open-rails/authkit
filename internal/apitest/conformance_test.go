package apitest_test

import (
	"encoding/json"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/httpapi"
)

// Every JSON API response these suites receive is checked against the route
// catalog: a success is a status the route declares with the body it
// declares, member for member (nulls only where the contract has them, lists
// never null, times in UTC); a failure is the error envelope with a catalog
// code at that code's status. An unmatched path answers the JSON not_found
// or method_not_allowed.

type catalogRoute struct {
	httpapi.RouteSpec
	pattern *regexp.Regexp
}

var apiCatalog = func() []catalogRoute {
	var out []catalogRoute
	for _, r := range httpapi.Catalog() {
		if r.Surface != httpapi.SurfaceAPI {
			continue
		}
		pattern := regexp.MustCompile("^" + regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(regexp.QuoteMeta(r.Path), "[^/]+") + "$")
		out = append(out, catalogRoute{r, pattern})
	}
	return out
}()

func (a *api) conform(method, path string, res response) {
	route, ok := strings.CutPrefix(path, strings.TrimSuffix(a.prefix, "/"))
	if !ok {
		return
	}
	var matched *catalogRoute
	for i, r := range apiCatalog {
		if (r.Method == method || method == http.MethodHead && r.Method == http.MethodGet) && r.pattern.MatchString(route) {
			// A literal segment outranks a wildcard, as in ServeMux.
			if matched == nil || strings.Count(matched.Path, "{") > strings.Count(r.Path, "{") {
				matched = &apiCatalog[i]
			}
		}
	}
	fail := func(format string, args ...any) {
		a.t.Errorf("contract: %s %s answered %d: "+format+"\n%s", append([]any{method, path, res.status}, append(args, res.String())...)...)
	}
	if len(res.body) > 0 && !strings.HasPrefix(res.header.Get("Content-Type"), "application/json") {
		fail("Content-Type %q", res.header.Get("Content-Type"))
		return
	}
	if res.status >= 400 {
		conformError(res, fail)
		return
	}
	if matched == nil {
		fail("a success for a path the catalog does not have")
		return
	}
	i := slices.IndexFunc(matched.Responses, func(r httpapi.Reply) bool { return r.Status == res.status })
	if i < 0 {
		fail("not a status %s %s declares", matched.Method, matched.Path)
		return
	}
	body := matched.Responses[i].Body
	if body == nil || method == http.MethodHead {
		if len(res.body) > 0 {
			fail("a body where the contract has none")
		}
		return
	}
	var v any
	if err := json.Unmarshal(res.body, &v); err != nil {
		fail("not JSON: %v", err)
		return
	}
	if diffs := httpapi.Conform(reflect.TypeOf(body), v); len(diffs) > 0 {
		fail("differs from %T:\n  %s", body, strings.Join(diffs, "\n  "))
	}
}

func conformError(res response, fail func(string, ...any)) {
	var env map[string]map[string]any
	if err := json.Unmarshal(res.body, &env); err != nil || len(env) != 1 || env["error"] == nil {
		fail("not the error envelope")
		return
	}
	obj := env["error"]
	members := make([]string, 0, len(obj))
	for k := range obj {
		members = append(members, k)
	}
	slices.Sort(members)
	if !slices.Equal(members, []string{"code", "message", "metadata", "param", "type"}) {
		fail("error members %v", members)
	}
	code, _ := obj["code"].(string)
	if !slices.Contains(errmodel.Codes(), errmodel.Code(code)) {
		fail("code %q is not in the catalog", code)
		return
	}
	if want := errmodel.Status(errmodel.Code(code)); want != res.status {
		fail("%s is %d in the catalog", code, want)
	}
}
