package authhttp

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
)

// buildRedirectURI computes the OAuth/OIDC redirect_uri for this request's flow.
//
// SECURITY (AK F2): the scheme+host come from the TRUSTED server config
// (Config().Frontend.BaseURL), never from attacker-controllable X-Forwarded-Proto /
// X-Forwarded-Host request headers. An attacker who could set X-Forwarded-Host
// would otherwise steer the redirect_uri — and thus the authorization code —
// to a host they control. When no BaseURL is configured (local/dev) we fall
// back to the request's own connection scheme + Host header, still never the
// forwarded headers.
func (s *Service) buildRedirectURI(r *http.Request, provider string) string {
	if r == nil {
		return ""
	}
	p := oidcCallbackPath(r.URL.Path, provider)
	if origin, ok := originFromBaseURL(s.svc.Config().Frontend.BaseURL); ok {
		return origin + p
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + p
}

// oidcCallbackPath derives the callback path for a given start path + provider.
func oidcCallbackPath(p, provider string) string {
	switch {
	case strings.HasSuffix(p, "/login"):
		return strings.TrimSuffix(p, "/login") + "/callback"
	case strings.HasSuffix(p, "/link/start"):
		return strings.TrimSuffix(p, "/link/start") + "/callback"
	case strings.HasSuffix(p, "/step-up/start"):
		return strings.TrimSuffix(p, "/step-up/start") + "/step-up/callback"
	default:
		if i := strings.Index(p, "/oidc/"); i >= 0 {
			return p[:i] + "/oidc/" + provider + "/callback"
		}
		return "/oidc/" + provider + "/callback"
	}
}

func originFromBaseURL(baseURL string) (origin string, ok bool) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u == nil {
		return "", false
	}
	if u.Scheme == "" || u.Host == "" {
		return "", false
	}
	return u.Scheme + "://" + u.Host, true
}

// --- OAuth/OIDC state-to-browser binding (AK F3) ---

// The state cookie binds the OAuth/OIDC `state` to the browser that started the
// flow. Without it, an attacker can complete a login with their OWN IdP identity,
// capture the resulting state+code, and trick a victim's browser into hitting the
// callback — silently logging the victim into the ATTACKER's account (login CSRF).
// Its names are in the cookie registry (cookies.go).
const oauthStateCookieTTL = 15 * time.Minute

// stateCookieName keys the cookie by the flow's state so two flows started in
// one browser never clobber each other's cookie (#323).
func stateCookieName(state string) string { return oidcStatePrefix + stateCookieSuffix(state) }

func stateCookieSuffix(state string) string {
	sum := sha256.Sum256([]byte(state))
	return hex.EncodeToString(sum[:4])
}

// stateCookie is the one shape of the flow's state cookie — set and clear
// share it so the clearing Set-Cookie carries the same Secure/SameSite
// attributes as the cookie it evicts. SameSite=Lax (not Strict) is required so
// the cookie is sent on the cross-site top-level GET navigation back from the
// IdP to the callback. A response_mode=form_post provider (Apple) returns a
// cross-site POST, which browsers do not attach Lax cookies to, so only those
// providers get SameSite=None; Secure (#295) — authhttp.New refuses form_post
// on non-HTTPS deployments.
//
// A Secure state cookie carries the __Host- prefix (host-only, Path=/), so a
// sibling subdomain cannot plant or shadow it; plain-HTTP dev keeps the bare
// name, which browsers require there.
func (s *Service) stateCookie(r *http.Request, p authprovider.Provider, state, value string, maxAge int) *http.Cookie {
	c := &http.Cookie{
		Name:     s.stateCookieName(r, p, state),
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.stateCookieSecure(r, p),
		SameSite: http.SameSiteLaxMode,
	}
	if p.ResponseModeFormPost() {
		c.SameSite = http.SameSiteNoneMode
	}
	return c
}

func (s *Service) stateCookieSecure(r *http.Request, p authprovider.Provider) bool {
	return p.ResponseModeFormPost() || s.cookieSecure(r)
}

func (s *Service) stateCookieName(r *http.Request, p authprovider.Provider, state string) string {
	return currentCookie(cookieOIDCState, s.stateCookieSecure(r, p)).Name + stateCookieSuffix(state)
}

// setStateCookie stores the flow's state in an HttpOnly cookie.
func (s *Service) setStateCookie(w http.ResponseWriter, r *http.Request, p authprovider.Provider, state string) {
	http.SetCookie(w, s.stateCookie(r, p, state, state, int(oauthStateCookieTTL.Seconds())))
}

// maxCallbackFormBytes bounds a form_post authorization response: state, code,
// id_token and a small user object.
const maxCallbackFormBytes = 64 << 10

// callbackParams returns the IdP's authorization response: the query string of
// the GET redirect, or the form body of a response_mode=form_post POST. An
// oversized body yields no parameters.
func callbackParams(r *http.Request) url.Values {
	if r.Method == http.MethodPost {
		if r.PostForm == nil {
			r.Body = http.MaxBytesReader(nil, r.Body, maxCallbackFormBytes)
			if err := r.ParseForm(); err != nil {
				r.PostForm = url.Values{}
			}
		}
		return r.PostForm
	}
	return r.URL.Query()
}

// clearStateCookie expires this flow's state cookie (single-use); other flows'
// cookies are untouched.
func (s *Service) clearStateCookie(w http.ResponseWriter, r *http.Request, p authprovider.Provider, state string) {
	http.SetCookie(w, s.stateCookie(r, p, state, "", -1))
	// A flow begun before an upgrade left a historical variant; never read, it
	// is only removed.
	current := currentCookie(cookieOIDCState, s.stateCookieSecure(r, p))
	suffix := stateCookieSuffix(state)
	expireCookieVariants(w, r, cookieOIDCState, &current, s.stateCookieSecure(r, p), func(v cookieVariant) string { return v.Name + suffix }, "", true)
}

// stateCookieMatches reports whether the request carries the state cookie and it
// equals state (constant-time). Callbacks MUST reject a missing/mismatched cookie
// before consuming the server-side state.
func (s *Service) stateCookieMatches(r *http.Request, p authprovider.Provider, state string) bool {
	if strings.TrimSpace(state) == "" {
		return false
	}
	c, err := r.Cookie(s.stateCookieName(r, p, state))
	if err != nil || c == nil || c.Value == "" {
		return false
	}
	return embedded.SecretEqual(c.Value, state)
}

// cookieSecure reports whether auth cookies should carry the Secure attribute:
// true whenever the deployment is HTTPS (BaseURL scheme, or the request's own
// TLS). Local http dev gets non-Secure cookies so the flow still works.
func (s *Service) cookieSecure(r *http.Request) bool {
	if origin, ok := originFromBaseURL(s.svc.Config().Frontend.BaseURL); ok {
		return strings.HasPrefix(strings.ToLower(origin), "https://")
	}
	return r != nil && r.TLS != nil
}
