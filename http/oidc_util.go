package authhttp

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
)

func randB64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// A crypto/rand failure is unrecoverable, and randB64 backs
		// security-critical secrets (refresh tokens, password-reset / link /
		// email-verification tokens, OAuth state and nonce). The previous code
		// ignored this error, so on RNG failure it would emit a fully
		// predictable zero-filled token. Fail closed instead of silently
		// downgrading entropy.
		panic("authkit: crypto/rand unavailable: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func buildRedirectURI(r *http.Request, provider string) string {
	if r == nil {
		return ""
	}
	scheme := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	if host == "" {
		host = r.Host
	}

	p := r.URL.Path
	switch {
	case strings.HasSuffix(p, "/login"):
		p = strings.TrimSuffix(p, "/login") + "/callback"
	case strings.HasSuffix(p, "/link/start"):
		p = strings.TrimSuffix(p, "/link/start") + "/callback"
	case strings.HasSuffix(p, "/reauth/start"):
		p = strings.TrimSuffix(p, "/reauth/start") + "/reauth/callback"
	default:
		if i := strings.Index(p, "/oidc/"); i >= 0 {
			prefix := p[:i]
			p = prefix + "/oidc/" + provider + "/callback"
		} else {
			p = "/oidc/" + provider + "/callback"
		}
	}
	return scheme + "://" + host + p
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
