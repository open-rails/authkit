package authhttp

// ak#271: deliver the rotating refresh token as an HttpOnly cookie instead of
// a JSON body field, so an injected script cannot read the durable credential.
//
// Opt-in per mount (MountOptions.RefreshCookie). A host that does not opt in
// sees byte-identical behaviour: nothing here runs without the mount-resolved
// policy in the request context, and the consume sites still read the body
// first.
//
// What this does NOT fix: script running in a live tab can still CALL the
// refresh route and mint access tokens. The cookie removes theft-and-replay
// from elsewhere, not abuse from inside the victim's own tab.

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// RefreshCookieName is the cookie the refresh token rides in.
const RefreshCookieName = "authkit_rt"

// refreshCookiePolicy is the mount-resolved cookie policy. It lives in the
// request context rather than on the Service so one Service mounted twice with
// different options cannot cross-contaminate.
type refreshCookiePolicy struct {
	// path is the mount's API anchor (APIPrefix). Both
	// refresh-consuming routes live under it — POST /token and
	// POST /sessions/current — and they do not share a tighter prefix. Anchoring
	// there keeps the cookie off the SPA document and its assets.
	path string
}

type refreshCookieCtxKey struct{}

// withRefreshCookiePolicy is applied by MountHandler when the host opts in.
func withRefreshCookiePolicy(next http.Handler, policy refreshCookiePolicy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), refreshCookieCtxKey{}, policy)))
	})
}

func refreshCookieEnabled(r *http.Request) (refreshCookiePolicy, bool) {
	if r == nil {
		return refreshCookiePolicy{}, false
	}
	p, ok := r.Context().Value(refreshCookieCtxKey{}).(refreshCookiePolicy)
	return p, ok
}

// setRefreshCookie writes the rotating refresh token to the browser.
//
// SameSite=Lax, never Strict. The OIDC tail is a cross-site top-level GET from
// the IdP into /{provider}/callback and then a redirect on to the SPA; Strict
// withholds the cookie for navigations begun cross-site, so the landing page's
// first refresh fails. Emailed verification/magic links land the same way. Lax
// still blocks the cross-site POST that a CSRF against the refresh route would
// need. AuthKit's own OAuth state cookie already documents the same constraint
// — two auth cookies on one flow with different SameSite is a trap.
//
// Secure follows the deployment (cookieSecure): plain-http local dev would
// otherwise never receive the cookie at all.
func (s *Service) setRefreshCookie(w http.ResponseWriter, r *http.Request, value string) {
	policy, ok := refreshCookieEnabled(r)
	if !ok || strings.TrimSpace(value) == "" {
		return
	}
	c := &http.Cookie{
		Name:     RefreshCookieName,
		Value:    value,
		Path:     policy.path,
		HttpOnly: true,
		Secure:   s.cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	}
	// A finite refresh TTL mirrors onto the jar; an indefinite session
	// (RefreshTokenDuration <= 0) gets a session cookie, matching the server.
	if d := s.svc.Config().Token.RefreshTokenDuration; d > 0 {
		c.MaxAge = int(d.Seconds())
	}
	http.SetCookie(w, c)
}

// clearRefreshCookie expires the cookie.
//
// Separate function on purpose, with no caller-supplied MaxAge: net/http omits
// the attribute entirely for MaxAge == 0, which yields a *session* cookie — a
// shared (value, maxAge) helper produces a "clear" that does not clear. Only
// MaxAge < 0 serializes Max-Age=0. Every other attribute must match the setter
// or the browser keeps the original cookie alongside the tombstone.
func (s *Service) clearRefreshCookie(w http.ResponseWriter, r *http.Request) {
	policy, ok := refreshCookieEnabled(r)
	if !ok {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshCookieName,
		Value:    "",
		Path:     policy.path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// refreshTokenFromRequest resolves the refresh credential for a consuming
// route: the request body wins, the cookie is the fallback.
//
// Body-first is deliberate. A client that still holds a body token is mid
// migration and its token is the one the server last rotated; preferring the
// cookie there would spend a credential the client does not know was spent.
//
// Duplicate cookies fail CLOSED. `r.Cookie` returns the first match, and the
// browser orders longest-Path-first, so a sibling host that can set
// Domain=<parent> plants a cookie that shadows the victim's host-only one and
// the session silently becomes the attacker's. Two values is never legitimate.
func (s *Service) refreshTokenFromRequest(r *http.Request, body string) (string, bool) {
	if t := strings.TrimSpace(body); t != "" {
		return t, true
	}
	if _, ok := refreshCookieEnabled(r); !ok {
		return "", false
	}
	var found string
	for _, c := range r.Cookies() {
		if c.Name != RefreshCookieName {
			continue
		}
		if found != "" {
			return "", false
		}
		found = strings.TrimSpace(c.Value)
	}
	if found == "" {
		return "", false
	}
	// A cookie-sourced credential is CSRF-relevant in a way a body token is
	// not, so it also has to survive the origin gate.
	if !s.cookieOriginAllowed(r) {
		return "", false
	}
	return found, true
}

// cookieOriginAllowed reports whether a cookie-sourced credential may be
// honored. SameSite=Lax already blocks the cross-site POST; this is the belt
// for clients and proxies that strip it.
//
// The test is Origin's HOST against the host the request was addressed to, or
// the configured Frontend.BaseURL's. Both are needed and neither alone is
// enough: r.Host covers a deployment reached by an alias or by 127.0.0.1 when
// BaseURL says localhost, and the configured host covers a proxy that rewrites
// Host. HOST, not full origin, because a TLS-terminating proxy leaves r.TLS nil
// and a scheme comparison would then reject every real production request while
// the browser correctly reports https. X-Forwarded-* is never consulted — it is
// attacker-settable and would let a cross-site request declare itself
// same-origin.
//
// A browser will not let a cross-site page forge Origin, and an off-browser
// caller that forges both does not hold the victim's cookie, so this is a sound
// same-origin test rather than a guess.
//
// Absent Origin is allowed: same-origin top-level navigations and non-browser
// callers legitimately omit it, and refusing them breaks flows this change
// exists to preserve. Present-and-mismatched is refused.
func (s *Service) cookieOriginAllowed(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" || strings.EqualFold(origin, "null") {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	configured, ok := originFromBaseURL(s.svc.Config().Frontend.BaseURL)
	if !ok {
		return false
	}
	cu, err := url.Parse(configured)
	return err == nil && cu.Host != "" && strings.EqualFold(u.Host, cu.Host)
}
