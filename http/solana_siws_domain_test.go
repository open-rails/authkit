package authhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSIWSRequestDomain(t *testing.T) {
	cases := []struct {
		name       string
		configured string
		origin     string
		host       string
		want       string
	}{
		{name: "configured wins", configured: "app.example.com", origin: "https://evil.com", host: "h:8080", want: "app.example.com"},
		{name: "origin https", origin: "https://app.example.com", host: "ignored", want: "app.example.com"},
		{name: "origin with port", origin: "https://app.example.com:8443/path", want: "app.example.com"},
		{name: "origin with userinfo", origin: "https://user:pw@app.example.com/x", want: "app.example.com"},
		{name: "origin ipv6", origin: "http://[::1]:3000", want: "::1"},
		{name: "host fallback", host: "app.example.com:8080", want: "app.example.com"},
		{name: "host fallback no port", host: "app.example.com", want: "app.example.com"},
		{name: "host ipv6", host: "[::1]:443", want: "::1"},
		{name: "empty everything", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/solana/challenge", nil)
			req.Host = tc.host
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if got := siwsRequestDomain(tc.configured, req); got != tc.want {
				t.Fatalf("siwsRequestDomain() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSIWSRequestDomainNilRequest(t *testing.T) {
	if got := siwsRequestDomain("cfg.example.com", nil); got != "cfg.example.com" {
		t.Fatalf("configured should win even with nil request, got %q", got)
	}
	if got := siwsRequestDomain("", nil); got != "" {
		t.Fatalf("nil request with no config should be empty, got %q", got)
	}
}
