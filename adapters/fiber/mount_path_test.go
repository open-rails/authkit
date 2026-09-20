package authkitfiber

import "testing"

func TestFiberRoutePath(t *testing.T) {
	for _, tc := range []struct{ httpPath, fiberPath string }{
		{"/api/v1/me", "/api/v1/me"},
		{"/.well-known/jwks.json", "/.well-known/jwks.json"},
		{"/api/v1/admin/users/{user_id}", "/api/v1/admin/users/:user_id"},
		{"/groups/{group_id}/members/{member_id}", "/groups/:group_id/members/:member_id"},
	} {
		got, err := fiberRoutePath(tc.httpPath)
		if err != nil || got != tc.fiberPath {
			t.Errorf("fiberRoutePath(%q) = %q, %v; want %q", tc.httpPath, got, err, tc.fiberPath)
		}
	}
	for _, path := range []string{
		"", "not-rooted", "/", "/subtree/", "/files/{rest...}", "/exact/{$}",
		"/bad/{name", "/bad/name}", "/bad/{x-y}", "/bad/{0name}", "/bad/{}",
		"/literal:parameter", "/wildcard/*", "/wildcard/+", "/optional?", "/escaped%2Fslash",
	} {
		if _, err := fiberRoutePath(path); err == nil {
			t.Errorf("unsupported path %q accepted", path)
		}
	}
}
