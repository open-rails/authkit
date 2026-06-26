package authkit

import (
	"net/url"
	"strings"
)

// NormalizeAllowedOrigin validates one browser Origin value and returns its
// canonical exact-match form. It accepts only scheme+host(+port), never paths,
// queries, fragments, userinfo, wildcards, or the special "null" origin.
func NormalizeAllowedOrigin(origin string) (string, error) {
	origin = strings.TrimSpace(origin)
	if origin == "" || strings.EqualFold(origin, "null") || strings.Contains(origin, "*") {
		return "", ErrInvalidRemoteApplication
	}
	u, err := url.Parse(origin)
	if err != nil || u == nil {
		return "", ErrInvalidRemoteApplication
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", ErrInvalidRemoteApplication
	}
	return scheme + "://" + strings.ToLower(u.Host), nil
}

// NormalizeAllowedOrigins validates, trims, normalizes, and de-duplicates exact
// browser origins for a remote_application.
func NormalizeAllowedOrigins(origins []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(origins))
	for _, raw := range origins {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		origin, err := NormalizeAllowedOrigin(raw)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[origin]; ok {
			continue
		}
		seen[origin] = struct{}{}
		out = append(out, origin)
	}
	return out, nil
}

// OriginAllowed reports whether origin exactly matches one of allowedOrigins.
func OriginAllowed(origin string, allowedOrigins []string) bool {
	origin, err := NormalizeAllowedOrigin(origin)
	if err != nil {
		return false
	}
	for _, allowed := range allowedOrigins {
		allowed, err := NormalizeAllowedOrigin(allowed)
		if err != nil {
			continue
		}
		if origin == allowed {
			return true
		}
	}
	return false
}
