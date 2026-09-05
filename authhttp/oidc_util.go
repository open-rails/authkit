package authhttp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-rails/authkit/authprovider"
)

func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

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

// oauthStateCookie binds the OAuth/OIDC `state` to the browser that started the
// flow. Without it, an attacker can complete a login with their OWN IdP identity,
// capture the resulting state+code, and trick a victim's browser into hitting the
// callback — silently logging the victim into the ATTACKER's account (login CSRF).
const oauthStateCookie = "authkit_oauth_state"

const oauthStateCookieTTL = 15 * time.Minute

// stateCookieName keys the cookie by the flow's state so two flows started in
// one browser never clobber each other's cookie (#323).
func stateCookieName(state string) string {
	sum := sha256.Sum256([]byte(state))
	return oauthStateCookie + "_" + hex.EncodeToString(sum[:4])
}

// setStateCookie stores the flow's state in an HttpOnly cookie. SameSite=Lax
// (not Strict) is required so the cookie is sent on the cross-site top-level GET
// navigation back from the IdP to the callback. A response_mode=form_post
// provider (Apple) returns a cross-site POST, which browsers do not attach Lax
// cookies to, so only those providers get SameSite=None; Secure (#295) —
// NewServer refuses form_post on non-HTTPS deployments.
func (s *Service) setStateCookie(w http.ResponseWriter, r *http.Request, p authprovider.Provider, state string) {
	c := &http.Cookie{
		Name:     stateCookieName(state),
		Value:    state,
		Path:     "/",
		MaxAge:   int(oauthStateCookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   s.cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	}
	if p.ResponseModeFormPost() {
		c.SameSite = http.SameSiteNoneMode
		c.Secure = true
	}
	http.SetCookie(w, c)
}

// callbackParams returns the IdP's authorization response: the query string of
// the GET redirect, or the form body of a response_mode=form_post POST.
func callbackParams(r *http.Request) url.Values {
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		return r.PostForm
	}
	return r.URL.Query()
}

// clearStateCookie expires this flow's state cookie (single-use); other flows'
// cookies are untouched.
func clearStateCookie(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName(state),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// stateCookieMatches reports whether the request carries the state cookie and it
// equals state (constant-time). Callbacks MUST reject a missing/mismatched cookie
// before consuming the server-side state.
func stateCookieMatches(r *http.Request, state string) bool {
	if strings.TrimSpace(state) == "" {
		return false
	}
	c, err := r.Cookie(stateCookieName(state))
	if err != nil || c == nil || c.Value == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(state)) == 1
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
