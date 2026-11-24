package netguard

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	for _, c := range []struct {
		ip      string
		private bool
	}{
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2606:4700:4700::1111", false},
		{"0.0.0.0", true},
		{"10.1.2.3", true},
		{"100.64.0.1", true},
		{"127.0.0.1", true},
		{"169.254.169.254", true},
		{"172.16.0.1", true},
		{"192.0.0.8", true},
		{"192.0.2.1", true},
		{"192.168.1.1", true},
		{"198.18.0.1", true},
		{"198.51.100.1", true},
		{"203.0.113.1", true},
		{"224.0.0.1", true},
		{"240.0.0.1", true},
		{"255.255.255.255", true},
		{"::", true},
		{"::1", true},
		{"::ffff:127.0.0.1", true},
		{"::ffff:169.254.169.254", true},
		{"::ffff:8.8.8.8", false},
		{"::127.0.0.1", true},           // IPv4-compatible
		{"::8.8.8.8", true},             // IPv4-compatible, deprecated
		{"64:ff9b::7f00:1", true},       // NAT64 to 127.0.0.1
		{"64:ff9b::a9fe:a9fe", true},    // NAT64 to 169.254.169.254
		{"64:ff9b::a00:1", true},        // NAT64 to 10.0.0.1
		{"64:ff9b::808:808", false},     // NAT64 to 8.8.8.8
		{"64:ff9b:1::808:808", true},    // local-use NAT64
		{"100::1", true},                // discard-only
		{"2001::1", true},               // Teredo
		{"2001:db8::1", true},           // documentation
		{"2002:7f00:1::1", true},        // 6to4
		{"3fff::1", true},               // documentation
		{"fc00::1", true},               // unique local
		{"fd12:3456::1", true},          // unique local
		{"fe80::1", true},               // link-local
		{"fec0::1", true},               // site-local
		{"ff02::1", true},               // multicast
		{"2001:4860:4860::8888", false}, // public
	} {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test address %s", c.ip)
		}
		if got := IsPrivateIP(ip); got != c.private {
			t.Errorf("IsPrivateIP(%s) = %v, want %v", c.ip, got, c.private)
		}
	}
	if !IsPrivateIP(nil) {
		t.Error("nil is public")
	}
}

// The redirect policy, through Client against real local servers.
func TestClientRedirects(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/hop/")); err == nil && n > 0 {
			http.Redirect(w, r, "/hop/"+strconv.Itoa(n-1), http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/downgrade":
			http.Redirect(w, r, plain.URL+"/hop/0", http.StatusFound)
		case "/secure":
			http.Redirect(w, r, "/done", http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer secure.Close()
	c := Client(0, true)
	roots := x509.NewCertPool()
	roots.AddCert(secure.Certificate())
	c.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: roots}
	get := func(url string) error {
		res, err := c.Get(url)
		if err == nil {
			res.Body.Close()
		}
		return err
	}
	if err := get(secure.URL + "/secure"); err != nil {
		t.Fatalf("https to https: %v", err)
	}
	if err := get(secure.URL + "/downgrade"); err == nil || !strings.Contains(err.Error(), "from https") {
		t.Fatalf("https to http followed: %v", err)
	}
	if err := get(plain.URL + "/hop/" + strconv.Itoa(MaxRedirects)); err != nil {
		t.Fatalf("%d redirects: %v", MaxRedirects, err)
	}
	if err := get(plain.URL + "/hop/" + strconv.Itoa(MaxRedirects+1)); err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Fatalf("%d redirects followed: %v", MaxRedirects+1, err)
	}
}
