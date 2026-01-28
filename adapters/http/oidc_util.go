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
	_, _ = rand.Read(b)
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
	default:
		if i := strings.Index(p, "/auth/oidc/"); i >= 0 {
			prefix := p[:i]
			p = prefix + "/auth/oidc/" + provider + "/callback"
		} else {
			p = "/auth/oidc/" + provider + "/callback"
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
