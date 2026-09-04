package authhttp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestWithTrustedProxies pins #143 and ak#298: X-Forwarded-For is honoured ONLY
// from a declared proxy peer, CF-Connecting-IP ONLY from a Cloudflare peer (and
// only when X-Forwarded-For is absent), the direct peer is used otherwise, and an
// invalid CIDR fails construction rather than silently mis-trusting.
func TestWithTrustedProxies(t *testing.T) {
	cfg := newServerTestConfig()
	build := func(t *testing.T, opts ...Option) *Service {
		t.Helper()
		srv, err := NewServer(newServerClient(t, cfg, newNoDBPool(t)), opts...)
		require.NoError(t, err)
		return srv
	}
	req := func(peer string, headers map[string]string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = peer
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return r
	}
	trusted := WithTrustedProxies("10.0.0.0/8")
	cloudflare := WithCloudflareProxies("103.21.244.0/22")

	t.Run("trusts X-Forwarded-For from a trusted peer", func(t *testing.T) {
		srv := build(t, trusted)
		require.Equal(t, "203.0.113.7", srv.clientIP(req("10.1.2.3:443", map[string]string{"X-Forwarded-For": "203.0.113.7"})))
	})

	t.Run("ignores X-Forwarded-For from an untrusted peer", func(t *testing.T) {
		srv := build(t, trusted)
		require.Equal(t, "198.51.100.9", srv.clientIP(req("198.51.100.9:443", map[string]string{"X-Forwarded-For": "203.0.113.7"})))
	})

	t.Run("trusted peer never honours CF-Connecting-IP", func(t *testing.T) {
		srv := build(t, trusted)
		require.Equal(t, "10.1.2.3", srv.clientIP(req("10.1.2.3:443", map[string]string{"CF-Connecting-IP": "203.0.113.99"})))
		require.Equal(t, "203.0.113.7", srv.clientIP(req("10.1.2.3:443", map[string]string{
			"CF-Connecting-IP": "203.0.113.99", "X-Forwarded-For": "203.0.113.7",
		})))
	})

	t.Run("cloudflare peer honours CF-Connecting-IP only without X-Forwarded-For", func(t *testing.T) {
		srv := build(t, cloudflare)
		require.Equal(t, "203.0.113.99", srv.clientIP(req("103.21.244.5:443", map[string]string{"CF-Connecting-IP": "203.0.113.99"})))
		require.Equal(t, "203.0.113.7", srv.clientIP(req("103.21.244.5:443", map[string]string{
			"CF-Connecting-IP": "203.0.113.99", "X-Forwarded-For": "203.0.113.50, 203.0.113.7",
		})))
		require.Equal(t, "103.21.244.5", srv.clientIP(req("103.21.244.5:443", map[string]string{"CF-Connecting-IP": "10.9.9.9"})))
	})

	t.Run("cloudflare hop behind a trusted proxy is skipped in the walk", func(t *testing.T) {
		srv := build(t, trusted, cloudflare)
		require.Equal(t, "203.0.113.7", srv.clientIP(req("10.1.2.3:443", map[string]string{
			"X-Forwarded-For": "203.0.113.50, 203.0.113.7, 103.21.244.5",
		})))
	})

	t.Run("WithClientIPFunc wins over proxy sets", func(t *testing.T) {
		srv := build(t, trusted, WithClientIPFunc(func(*http.Request) string { return "fixed" }))
		require.Equal(t, "fixed", srv.clientIP(req("10.1.2.3:443", map[string]string{"X-Forwarded-For": "203.0.113.7"})))
	})

	t.Run("invalid CIDR fails NewServer", func(t *testing.T) {
		_, err := NewServer(newServerClient(t, cfg, newNoDBPool(t)), WithTrustedProxies("not-a-cidr"))
		require.Error(t, err)
		_, err = NewServer(newServerClient(t, cfg, newNoDBPool(t)), WithCloudflareProxies("not-a-cidr"))
		require.Error(t, err)
	})
}

// TestClientIPTrustScope_LimiterKey proves on the real mount that a spoofed
// CF-Connecting-IP behind a plain trusted proxy cannot rotate the per-IP
// rate-limit key, while the same header from a Cloudflare peer does select it.
func TestClientIPTrustScope_LimiterKey(t *testing.T) {
	pool := newServerTestPool(t)
	post := func(srv *Service, peer, cfIP string, n int) int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/email/password/reset/request", strings.NewReader(fmt.Sprintf(`{"email":"spoof-%d@example.com"}`, n)))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = peer
		r.Header.Set("CF-Connecting-IP", cfIP)
		srv.APIHandler().ServeHTTP(w, r)
		return w.Code
	}

	t.Run("trusted peer: rotating CF-Connecting-IP shares one bucket", func(t *testing.T) {
		srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool), WithTrustedProxies("10.0.0.0/8"))
		require.NoError(t, err)
		require.NotEqual(t, http.StatusTooManyRequests, post(srv, "10.1.2.3:443", "203.0.113.1", 1))
		require.Equal(t, http.StatusTooManyRequests, post(srv, "10.1.2.3:443", "203.0.113.2", 2), "spoofed header must not mint a fresh per-IP key")
	})

	t.Run("cloudflare peer: CF-Connecting-IP is the key", func(t *testing.T) {
		srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool), WithCloudflareProxies("103.21.244.0/22"))
		require.NoError(t, err)
		require.NotEqual(t, http.StatusTooManyRequests, post(srv, "103.21.244.5:443", "203.0.113.1", 1))
		require.NotEqual(t, http.StatusTooManyRequests, post(srv, "103.21.244.5:443", "203.0.113.2", 2))
		require.Equal(t, http.StatusTooManyRequests, post(srv, "103.21.244.5:443", "203.0.113.2", 3), "same client IP is one bucket")
	})
}
