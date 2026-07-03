package authhttp

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestWithTrustedProxies pins #143: WithTrustedProxies is the normal proxy knob —
// forwarded headers are honored ONLY from a trusted-proxy peer, the direct peer is
// used otherwise, and an invalid CIDR fails construction rather than silently
// mis-trusting.
func TestWithTrustedProxies(t *testing.T) {
	cfg := newServerTestConfig()

	t.Run("trusts X-Forwarded-For from a trusted peer", func(t *testing.T) {
		srv, err := NewServer(newServerClient(t, cfg, newNoDBPool(t)), WithTrustedProxies("10.0.0.0/8"))
		require.NoError(t, err)
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.1.2.3:443"
		req.Header.Set("X-Forwarded-For", "203.0.113.7")
		require.Equal(t, "203.0.113.7", srv.clientIP(req))
	})

	t.Run("ignores X-Forwarded-For from an untrusted peer", func(t *testing.T) {
		srv, err := NewServer(newServerClient(t, cfg, newNoDBPool(t)), WithTrustedProxies("10.0.0.0/8"))
		require.NoError(t, err)
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "198.51.100.9:443" // not in 10.0.0.0/8
		req.Header.Set("X-Forwarded-For", "203.0.113.7")
		require.Equal(t, "198.51.100.9", srv.clientIP(req))
	})

	t.Run("invalid CIDR fails NewServer", func(t *testing.T) {
		_, err := NewServer(newServerClient(t, cfg, newNoDBPool(t)), WithTrustedProxies("not-a-cidr"))
		require.Error(t, err)
	})
}
