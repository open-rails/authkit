package verify

// Tests for the SSRF-guarding dialer (second layer: DNS-resolution time).
// The dialer rejects connections to private/reserved IPs even when the attacker
// supplies a public-looking hostname that DNS rebinds to an internal address.

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIsPrivateIP covers the key RFC ranges we must block.
func TestIsPrivateIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.255.255.255",
		"10.0.0.1", "10.255.255.255",
		"172.16.0.1", "172.31.255.255",
		"192.168.0.1", "192.168.255.255",
		"169.254.169.254", // AWS/GCP metadata
		"169.254.0.1",
		"100.64.0.1", // carrier-grade NAT
		"::1",        // IPv6 loopback
		"fe80::1",    // IPv6 link-local
		"fc00::1",    // IPv6 unique local
		"0.0.0.0",
	}
	for _, s := range blocked {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test setup: cannot parse IP %q", s)
		}
		if !isPrivateIP(ip) {
			t.Errorf("isPrivateIP(%q) = false, want true", s)
		}
	}

	allowed := []string{
		"1.1.1.1",      // Cloudflare DNS (public)
		"8.8.8.8",      // Google DNS (public)
		"2606:4700::1", // Cloudflare IPv6 (public)
	}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test setup: cannot parse IP %q", s)
		}
		if isPrivateIP(ip) {
			t.Errorf("isPrivateIP(%q) = true, want false", s)
		}
	}
}

// TestSSRFGuardDialer_BlocksPrivateLiteralIP verifies the dialer refuses to
// connect when the address passed is already a private IP literal.
func TestSSRFGuardDialer_BlocksPrivateLiteralIP(t *testing.T) {
	_, err := ssrfGuardDialer(context.Background(), "tcp", "127.0.0.1:80")
	if err == nil {
		t.Fatal("expected error dialing loopback, got nil")
	}
}

// TestSSRFGuardDialer_BlocksPrivateLiteralIPv6 covers the IPv6 loopback case.
func TestSSRFGuardDialer_BlocksPrivateLiteralIPv6(t *testing.T) {
	_, err := ssrfGuardDialer(context.Background(), "tcp", "[::1]:80")
	if err == nil {
		t.Fatal("expected error dialing IPv6 loopback, got nil")
	}
}

// TestNewSSRFGuardedClient_BlocksLocalhostServer verifies the full stack:
// a guarded client cannot fetch from a local httptest.Server (127.0.0.1).
func TestNewSSRFGuardedClient_BlocksLocalhostServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewSSRFGuardedClient()
	_, err := client.Get(srv.URL) //nolint:noctx
	if err == nil {
		t.Fatal("guarded client reached localhost server — SSRF guard not working")
	}
}

