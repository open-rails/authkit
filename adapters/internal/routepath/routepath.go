// Package routepath holds the router-agnostic path helpers shared by AuthKit's
// gin and chi adapters: extracting {param} names, normalizing a mount prefix, and
// joining a prefix to a route path. Router-specific glue (gin SetPathValue, chi
// URLParam) stays in each adapter.
package routepath

import "strings"

// ParamNames returns the names of `{param}` segments in a net/http-style path.
func ParamNames(path string) []string {
	parts := strings.Split(path, "/")
	names := make([]string, 0)
	for _, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			names = append(names, strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}"))
		}
	}
	return names
}

// Clean normalizes a mount prefix: trimmed, leading slash, and "" for root.
func Clean(path string) string {
	path = "/" + strings.Trim(strings.TrimSpace(path), "/")
	if path == "/" {
		return ""
	}
	return path
}

// Join joins a mount prefix to a route path, yielding "/" when both are empty.
func Join(prefix, path string) string {
	prefix = Clean(prefix)
	path = "/" + strings.Trim(strings.TrimSpace(path), "/")
	if path == "/" {
		path = ""
	}
	if prefix == "" && path == "" {
		return "/"
	}
	return prefix + path
}
