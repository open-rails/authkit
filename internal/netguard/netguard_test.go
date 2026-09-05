package netguard

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	for _, s := range []string{
		"127.0.0.1", "127.255.255.255", "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255",
		"192.168.0.1", "192.168.255.255", "169.254.169.254", "169.254.0.1", "100.64.0.1",
		"::1", "fe80::1", "fc00::1", "0.0.0.0", "255.255.255.255", "240.0.0.1",
	} {
		if !IsPrivateIP(net.ParseIP(s)) {
			t.Errorf("IsPrivateIP(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "2606:4700::1"} {
		if IsPrivateIP(net.ParseIP(s)) {
			t.Errorf("IsPrivateIP(%q) = true, want false", s)
		}
	}
	if !IsPrivateIP(nil) {
		t.Error("IsPrivateIP(nil) must be true")
	}
}

func TestIsInternalHostname(t *testing.T) {
	for _, h := range []string{"localhost", "LOCALHOST", "foo.localhost", "metadata", "metadata.google.internal", "host.docker.internal", "x.docker.internal", "host.containers.internal", "host-gateway"} {
		if !IsInternalHostname(h) {
			t.Errorf("IsInternalHostname(%q) = false, want true", h)
		}
	}
	for _, h := range []string{"example.com", "auth.example.com", "internal.example.com"} {
		if IsInternalHostname(h) {
			t.Errorf("IsInternalHostname(%q) = true, want false", h)
		}
	}
}

type fakeResolver map[string][]string

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	var out []net.IPAddr
	for _, s := range f[host] {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

func TestDialerRefusesPrivateLiteralsAndAnswers(t *testing.T) {
	dial := DialerWith(fakeResolver{
		"loopback.example": {"127.0.0.1"},
		"mixed.example":    {"93.184.216.34", "10.0.0.5"},
		"metadata.example": {"169.254.169.254"},
		"empty.example":    nil,
	}, false)
	for _, addr := range []string{"127.0.0.1:80", "[::1]:80", "10.1.2.3:443", "loopback.example:80", "mixed.example:443", "metadata.example:80", "empty.example:80"} {
		if _, err := dial(context.Background(), "tcp", addr); err == nil {
			t.Errorf("dial %q succeeded, want refusal", addr)
		}
	}
}

func TestClientGuardBlocksLocalServerUnlessPrivateAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()

	if _, err := Client(0, false).Get(srv.URL); err == nil { //nolint:noctx
		t.Fatal("guarded client reached a loopback server")
	}
	resp, err := Client(0, true).Get(srv.URL) //nolint:noctx
	if err != nil {
		t.Fatalf("allowPrivate client: %v", err)
	}
	resp.Body.Close()
	if Client(0, true).Timeout != DefaultTimeout {
		t.Fatal("Client(0, ...) must default to DefaultTimeout")
	}
}
