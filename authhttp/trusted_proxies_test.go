package authhttp

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
)

// TestWithTrustedProxies pins #143 and ak#298: X-Forwarded-For is honoured ONLY
// from a declared proxy peer, CF-Connecting-IP ONLY from a Cloudflare peer (and
// only when X-Forwarded-For is absent), the direct peer is used otherwise, and an
// invalid CIDR fails construction rather than silently mis-trusting.
func TestWithTrustedProxies(t *testing.T) {
	cfg := newServerTestConfig()
	build := func(t *testing.T, opts ...Option) *Service {
		t.Helper()
		srv, err := NewServer(newServerClient(t, cfg, testdb.UnlockedPool(t)), opts...)
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
		_, err := NewServer(newServerClient(t, cfg, testdb.UnlockedPool(t)), WithTrustedProxies("not-a-cidr"))
		require.Error(t, err)
		_, err = NewServer(newServerClient(t, cfg, testdb.UnlockedPool(t)), WithCloudflareProxies("not-a-cidr"))
		require.Error(t, err)
	})
}

// TestClientIPTrustScope_LimiterKey proves on the real mount that a spoofed
// CF-Connecting-IP behind a plain trusted proxy cannot rotate the per-IP
// rate-limit key, while the same header from a Cloudflare peer does select it.
func TestClientIPTrustScope_LimiterKey(t *testing.T) {
	pool := testdb.Pool(t)
	post := func(srv *Service, peer, cfIP string, n int) int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/password/reset/request", strings.NewReader(fmt.Sprintf(`{"identifier":"spoof-%d@example.com"}`, n)))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = peer
		r.Header.Set("CF-Connecting-IP", cfIP)
		srv.apiHandler().ServeHTTP(w, r)
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

// TestNewServer_RequiresClientIPPosture pins ak#299: the host must declare how
// the client IP is derived, or construction fails.
func TestNewServer_RequiresClientIPPosture(t *testing.T) {
	rdb := testdb.ScratchRedis(t)
	prod := newServerTestConfig()
	prod.Ephemeral = embedded.EphemeralConfig{}
	prodClient := func() *embedded.Client { return newServerClient(t, prod, testdb.UnlockedPool(t), withRedis(rdb)) }

	_, err := NewServer(prodClient(), WithRedis(rdb))
	require.Error(t, err)
	require.Contains(t, err.Error(), "client-IP posture")

	for name, opt := range map[string]Option{
		"direct peer":       WithDirectPeerIP(),
		"trusted proxies":   WithTrustedProxies("10.0.0.0/8"),
		"cloudflare":        WithCloudflareProxies("103.21.244.0/22"),
		"explicit strategy": WithClientIPFunc(DefaultClientIP()),
	} {
		_, err := NewServer(prodClient(), WithRedis(rdb), opt)
		require.NoError(t, err, name)
	}

	// The memory store changes nothing: the posture is always required.
	_, err = NewServer(newServerClient(t, newServerTestConfig(), testdb.UnlockedPool(t)))
	require.Error(t, err)
	require.Contains(t, err.Error(), "client-IP posture")
}

// TestUndeclaredProxyTripwire pins the runtime half of ak#299: when the
// rate-limit key resolves to a private peer that carries forwarded headers, one
// ERROR line is logged per process; declaring the proxy silences it.
func TestUndeclaredProxyTripwire(t *testing.T) {
	pool := testdb.Pool(t)
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	const marker = "undeclared proxy is in front"
	post := func(srv *Service, peer string, headers map[string]string) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/password/reset/request", strings.NewReader(`{"identifier":"tripwire@example.com"}`))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = peer
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		srv.apiHandler().ServeHTTP(w, r)
	}

	srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool))
	require.NoError(t, err)
	post(srv, "10.0.0.5:1234", nil)
	require.Equal(t, 0, strings.Count(buf.String(), marker), "private peer without forwarded headers is not a proxy signal")
	post(srv, "10.0.0.5:1234", map[string]string{"X-Forwarded-For": "203.0.113.9"})
	post(srv, "10.0.0.5:1234", map[string]string{"CF-Connecting-IP": "203.0.113.9"})
	require.Equal(t, 1, strings.Count(buf.String(), marker), "exactly one tripwire line per process")

	buf.Reset()
	declared, err := NewServer(newServerClient(t, newServerTestConfig(), pool), WithTrustedProxies("10.0.0.0/8"))
	require.NoError(t, err)
	post(declared, "10.0.0.5:1234", map[string]string{"X-Forwarded-For": "203.0.113.9"})
	require.Equal(t, 0, strings.Count(buf.String(), marker), "declared proxy resolves to the public client; no tripwire")
}
