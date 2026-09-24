package authhttp

// Cookie compatibility registry (ak#395). Every cookie name/path/domain AuthKit
// has ever issued is listed here, current and historical. Setting, rotating or
// clearing a cookie expires the historical variants, and the refresh reader
// tolerates them, so upgrading AuthKit never strands a browser's session.
// TestCookieRegistry pins this list against the cookies AuthKit actually sets
// and against authhttp/testdata/cookie-registry.golden: a changed cookie shape
// must be added here as a new variant, never edited in place, and no variant
// may be removed. See docs/security/cookies.md.

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

type cookieKind string

const (
	cookieRefresh    cookieKind = "refresh"
	cookieOIDCState  cookieKind = "oidc_state"
	oidcStatePrefix             = "authkit_oauth_state_"
	tokenPathVariant            = "{api}/token" // the mount's POST /token path
)

// cookieVariant is one cookie shape AuthKit has issued. Path tokenPathVariant
// resolves against the mount's API prefix. An OIDC state name is a prefix
// completed by stateCookieName.
type cookieVariant struct {
	Kind   cookieKind
	Name   string
	Path   string
	Domain string // AuthKit never sets Domain: every variant is host-only
	Secure bool   // issued on HTTPS deployments (always true for __Host-)
	// Current marks the variant AuthKit issues now, per Secure mode.
	Current bool
	// Until is the last release that issued a historical variant.
	Until string
	// AcceptUntil lets the refresh reader fall back to a lone historical
	// variant until this date, migrating it. A historical plain-named cookie
	// can be planted by a sibling subdomain, so acceptance is time-boxed; after
	// it the variant is only expired. Zero means never read.
	AcceptUntil time.Time
}

var legacyAcceptUntil = time.Date(2026, time.December, 31, 0, 0, 0, 0, time.UTC)

// cookieRegistry is append-only.
var cookieRegistry = []cookieVariant{
	{Kind: cookieRefresh, Name: "authkit_rt", Path: tokenPathVariant, Until: "v0.136.0", AcceptUntil: legacyAcceptUntil},
	{Kind: cookieRefresh, Name: "authkit_rt", Path: tokenPathVariant, Secure: true, Until: "v0.136.0", AcceptUntil: legacyAcceptUntil},
	{Kind: cookieRefresh, Name: "authkit_rt", Path: "/", Current: true},
	{Kind: cookieRefresh, Name: "__Host-authkit_rt", Path: "/", Secure: true, Current: true},
	{Kind: cookieOIDCState, Name: oidcStatePrefix, Path: "/", Current: true},
	{Kind: cookieOIDCState, Name: oidcStatePrefix, Path: "/", Secure: true, Until: "v0.136.0"},
	{Kind: cookieOIDCState, Name: "__Host-" + oidcStatePrefix, Path: "/", Secure: true, Current: true},
}

func currentCookie(kind cookieKind, secure bool) cookieVariant {
	for _, v := range cookieRegistry {
		if v.Kind == kind && v.Current && v.Secure == secure {
			return v
		}
	}
	panic("authhttp: cookie registry has no current " + string(kind) + " variant")
}

// resolvedPath is the variant's concrete path on this mount.
func (v cookieVariant) resolvedPath(tokenPath string) string {
	if v.Path == tokenPathVariant {
		return tokenPath
	}
	return v.Path
}

// expired is the Set-Cookie that deletes the variant: name, path and domain
// identify a cookie. Secure follows the deployment (a browser only lets a
// secure origin overwrite a Secure cookie) and is required for __Host-.
func (v cookieVariant) expired(name, tokenPath string, secure bool) *http.Cookie {
	return &http.Cookie{Name: name, Value: "", Path: v.resolvedPath(tokenPath), Domain: v.Domain, MaxAge: -1,
		HttpOnly: true, Secure: secure || strings.HasPrefix(name, "__Host-"), SameSite: http.SameSiteLaxMode}
}

// expireCookieVariants deletes every variant of kind other than keep (nil:
// all of them); with presentOnly, only names the request carries. name
// completes a variant's name (the per-flow OIDC state suffix).
func expireCookieVariants(w http.ResponseWriter, r *http.Request, kind cookieKind, keep *cookieVariant, secure bool, name func(cookieVariant) string, tokenPath string, presentOnly bool) {
	done := map[string]bool{}
	for _, v := range cookieRegistry {
		n, path := name(v), v.resolvedPath(tokenPath)
		if v.Kind != kind || done[n+" "+path] || (keep != nil && keep.Name == v.Name && keep.resolvedPath(tokenPath) == path) {
			continue
		}
		if presentOnly {
			if _, err := r.Cookie(n); err != nil {
				continue
			}
		}
		done[n+" "+path] = true
		http.SetCookie(w, v.expired(n, tokenPath, secure))
	}
}

// refreshCookieCandidate reads the refresh token among the registry variants.
// The current variant wins; otherwise a lone historical one is accepted until
// its AcceptUntil. More values of one name than registered paths for it is a
// same-path duplicate (cookie tossing) and is refused outright. Browsers send
// longer paths first, so a full set of same-name values maps onto the name's
// paths in that order.
func refreshCookieCandidate(r *http.Request, secure bool, tokenPath string, now time.Time) (string, bool) {
	current := currentCookie(cookieRefresh, secure)
	values := map[string][]string{}
	var names []string
	for _, c := range r.Cookies() {
		if len(refreshPaths(c.Name, tokenPath)) == 0 {
			continue
		}
		if _, seen := values[c.Name]; !seen {
			names = append(names, c.Name)
		}
		values[c.Name] = append(values[c.Name], strings.TrimSpace(c.Value))
	}
	for _, name := range names {
		if len(values[name]) > len(refreshPaths(name, tokenPath)) {
			return "", false
		}
	}
	if vals := values[current.Name]; len(vals) > 0 {
		paths := refreshPaths(current.Name, tokenPath)
		if len(vals) == 1 {
			return vals[0], vals[0] != ""
		}
		for i, path := range paths {
			if path == current.Path {
				return vals[i], vals[i] != ""
			}
		}
	}
	var legacy []string
	for _, name := range names {
		if name == current.Name {
			continue
		}
		vals, paths := values[name], refreshPaths(name, tokenPath)
		for i, val := range vals {
			ok := false
			if len(vals) == 1 {
				ok = readableName(name, now)
			} else {
				ok = readable(name, paths[i], tokenPath, now)
			}
			if ok && val != "" {
				legacy = append(legacy, val)
			}
		}
	}
	if len(legacy) == 1 {
		return legacy[0], true
	}
	return "", false
}

// readable: the variant is still accepted as a fallback, or is the current
// variant of the other Secure mode (a deployment that switched scheme).
func readable(name, path, tokenPath string, now time.Time) bool {
	for _, v := range cookieRegistry {
		if v.Kind == cookieRefresh && v.Name == name && v.resolvedPath(tokenPath) == path && (v.Current || now.Before(v.AcceptUntil)) {
			return true
		}
	}
	return false
}

func readableName(name string, now time.Time) bool {
	for _, v := range cookieRegistry {
		if v.Kind == cookieRefresh && v.Name == name && (v.Current || now.Before(v.AcceptUntil)) {
			return true
		}
	}
	return false
}

// refreshPaths lists the distinct resolved paths registered for a refresh
// cookie name, longest first (the order browsers send them).
func refreshPaths(name, tokenPath string) []string {
	var paths []string
	for _, v := range cookieRegistry {
		p := v.resolvedPath(tokenPath)
		if v.Kind != cookieRefresh || v.Name != name || containsString(paths, p) {
			continue
		}
		paths = append(paths, p)
	}
	for i := 1; i < len(paths); i++ {
		for j := i; j > 0 && len(paths[j]) > len(paths[j-1]); j-- {
			paths[j], paths[j-1] = paths[j-1], paths[j]
		}
	}
	return paths
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// identity names a variant in testdata/cookie-registry.golden.
func (v cookieVariant) identity() string {
	return fmt.Sprintf("%s name=%s path=%s domain=%q secure=%v", v.Kind, v.Name, v.Path, v.Domain, v.Secure)
}
