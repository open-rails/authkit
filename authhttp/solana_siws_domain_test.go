package authhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The SIWS message domain is the protocol's anti-phishing anchor: it is what the
// wallet shows the user and what the signature commits to. This table walks the
// exact composition the challenge handler uses —
// siwsRequestDomain(siwsDomainFromConfig(baseURL, issuer), r) — over the shapes
// the old TrimPrefix+Index slicing got wrong.
func TestSIWSChallengeDomain(t *testing.T) {
	cases := []struct {
		name    string
		baseURL string
		issuer  string
		origin  string
		host    string
		want    string
	}{
		// Config wins; #143 says this is the production path.
		{name: "base url wins over everything", baseURL: "https://app.example.com", issuer: "https://iss.example.com", origin: "https://evil.example", host: "h:8080", want: "app.example.com"},
		{name: "base url port stripped", baseURL: "http://app.example.com:8443", want: "app.example.com"},
		{name: "issuer used when no base url", issuer: "https://iss.example.com/auth", origin: "https://evil.example", want: "iss.example.com"},

		// Origin fallback (local/dev): the shapes the slicing version broke on.
		{name: "origin plain", origin: "https://app.example.com", host: "ignored.example", want: "app.example.com"},
		{name: "origin with port", origin: "https://app.example.com:8443", want: "app.example.com"},
		{name: "origin with path", origin: "https://app.example.com/callback", want: "app.example.com"},
		{name: "origin with userinfo", origin: "https://user:pw@app.example.com", want: "app.example.com"},
		{name: "origin ipv6 literal", origin: "http://[::1]:3000", want: "::1"},
		{name: "origin garbage falls through to host", origin: "::::", host: "app.example.com:8080", want: "app.example.com"},

		// Host fallback.
		{name: "host with port", host: "app.example.com:8080", want: "app.example.com"},
		{name: "host bare", host: "app.example.com", want: "app.example.com"},
		{name: "host ipv6 literal", host: "[::1]:443", want: "::1"},
		{name: "host bare ipv6 literal", host: "[::1]", want: "::1"},

		{name: "nothing configured or sent", want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/solana/challenge", nil)
			req.Host = tc.host
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			got := siwsRequestDomain(siwsDomainFromConfig(tc.baseURL, tc.issuer), req)
			if got != tc.want {
				t.Fatalf("domain = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSIWSRequestDomainNilRequest(t *testing.T) {
	if got := siwsRequestDomain("cfg.example.com", nil); got != "cfg.example.com" {
		t.Fatalf("configured domain must win even with no request, got %q", got)
	}
	if got := siwsRequestDomain("", nil); got != "" {
		t.Fatalf("no config and no request must yield no domain, got %q", got)
	}
}
