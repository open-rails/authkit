package authhttp

// ak#271: deliver the rotating refresh token as an HttpOnly cookie instead of
// a JSON body field, so an injected script cannot read the durable credential.
//
// Opt-in per mount (MountOptions.RefreshCookie). A host that does not opt in
// keeps refresh tokens in JSON bodies. The mount-resolved request policy selects
// exactly one transport; there is no mixed-mode fallback.
//
// What this does NOT fix: script running in a live tab can still CALL the
// refresh route and mint access tokens. The cookie removes theft-and-replay
// from elsewhere, not abuse from inside the victim's own tab.

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RefreshCookieName is the refresh cookie on HTTPS deployments. Browsers accept
// a __Host- cookie only when it is Secure, host-only and Path=/, so a sibling
// subdomain can neither plant nor shadow it. Every name and path AuthKit has
// used lives in the cookie registry (cookies.go).
const RefreshCookieName = "__Host-authkit_rt"

// InsecureRefreshCookieName is used only on plain-HTTP deployments (local
// development), where browsers refuse __Host- cookies.
const InsecureRefreshCookieName = "authkit_rt"

// refreshCookiePolicy marks a mount that opted into the refresh cookie. It
// lives in the request context rather than on the Service so one Service
// mounted twice with different options cannot cross-contaminate. tokenPath is
// the mount's POST /token, where historical variants lived.
type refreshCookiePolicy struct{ tokenPath string }

func (s *Service) refreshCookie(r *http.Request) cookieVariant {
	return currentCookie(cookieRefresh, s.cookieSecure(r))
}

func variantName(v cookieVariant) string { return v.Name }

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
// otherwise never receive the cookie at all, and there the cookie drops the
// __Host- prefix. Path=/ is what __Host- requires; the cookie is HttpOnly and
// only POST /token reads it.
//
// Historical variants the browser still sends are expired alongside, so an
// upgraded deployment migrates each browser on its next session response.
func (s *Service) setRefreshCookie(w http.ResponseWriter, r *http.Request, value string) {
	policy, ok := refreshCookieEnabled(r)
	if !ok || strings.TrimSpace(value) == "" {
		return
	}
	current := s.refreshCookie(r)
	expireCookieVariants(w, r, cookieRefresh, &current, s.cookieSecure(r), variantName, policy.tokenPath, true)
	c := &http.Cookie{
		Name:     current.Name,
		Value:    value,
		Path:     "/",
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

// clearRefreshCookie expires the cookie and every historical variant.
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
	expireCookieVariants(w, r, cookieRefresh, nil, s.cookieSecure(r), variantName, policy.tokenPath, false)
}

// noRefreshCookie: a cookie mount's request carries no body token and no
// refresh cookie of any registered variant.
func (s *Service) noRefreshCookie(r *http.Request, body string) bool {
	policy, cookies := refreshCookieEnabled(r)
	if !cookies || strings.TrimSpace(body) != "" {
		return false
	}
	for _, c := range r.Cookies() {
		if len(refreshPaths(c.Name, policy.tokenPath)) > 0 {
			return false
		}
	}
	return true
}

// refreshTokenFromRequest follows the mount's declared transport. Cookie mounts
// reject body tokens and same-path duplicate cookies, and read historical
// variants through the registry; native mounts require a body token.
func (s *Service) refreshTokenFromRequest(r *http.Request, body string) (string, bool) {
	body = strings.TrimSpace(body)
	if _, cookies := refreshCookieEnabled(r); !cookies {
		return body, body != ""
	}
	if body != "" || !s.cookieOriginAllowed(r) {
		return "", false
	}
	policy, _ := refreshCookieEnabled(r)
	return refreshCookieCandidate(r, s.cookieSecure(r), policy.tokenPath, time.Now())
}

// cookieOriginAllowed guards cookie consumption and session establishment.
// Browser metadata can only narrow the declared deployment/request origin.
// Non-browser clients may omit Origin; opaque origins and cross-site requests
// cannot establish cookie sessions. Forwarded origin headers are never trusted.
func (s *Service) cookieOriginAllowed(r *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))) {
	case "", "same-origin", "none":
	default:
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	scheme := "http"
	if s.cookieSecure(r) {
		scheme = "https"
	}
	if strings.EqualFold(origin, scheme+"://"+r.Host) {
		return true
	}
	configured, ok := originFromBaseURL(s.svc.Config().Frontend.BaseURL)
	return ok && strings.EqualFold(origin, configured)
}
