package verify

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// privateIPBlocks lists address ranges that must never be the target of an
// outbound JWKS fetch. A superset of privateCoreCIDRs in the core package —
// the dialer layer sees the post-DNS-resolution IP, so it catches DNS rebinding
// that the registration-time hostname check cannot.
var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16", // AWS/GCP instance metadata endpoint
		"172.16.0.0/12",
		"192.168.0.0/16",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"240.0.0.0/4",
		"255.255.255.255/32",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
		"::/128",
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// ssrfGuardDialer is a DialContext function that resolves the target hostname,
// rejects any private/reserved IP in the result, then dials directly to the
// first resolved public IP. Dialing by IP (not hostname) prevents a second DNS
// lookup, closing the DNS-rebinding window between the check and the connect.
func ssrfGuardDialer(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("ssrf_guard: bad address %q: %v", addr, err)
	}

	// If addr is already a literal IP (Go's http.Transport resolves before dialing
	// when a proxy is in use, or when the host was already an IP), skip DNS.
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return nil, fmt.Errorf("ssrf_guard: IP %s is private/reserved — connection refused", ip)
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}

	// Resolve the hostname. Reject if ANY returned address is private.
	resolved, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("ssrf_guard: dns lookup %q: %v", host, err)
	}
	if len(resolved) == 0 {
		return nil, fmt.Errorf("ssrf_guard: no addresses returned for %q", host)
	}
	for _, a := range resolved {
		ip := net.ParseIP(a)
		if ip == nil {
			return nil, fmt.Errorf("ssrf_guard: unparseable IP %q for host %q", a, host)
		}
		if isPrivateIP(ip) {
			return nil, fmt.Errorf("ssrf_guard: %q resolved to private/reserved IP %s — connection refused", host, ip)
		}
	}

	// Dial directly to the first resolved IP — not the original hostname — so
	// the OS/resolver cannot issue a second lookup and return a different (private)
	// address between our check and the actual connect (DNS-rebinding attack).
	var d net.Dialer
	return d.DialContext(ctx, network, net.JoinHostPort(resolved[0], port))
}

// NewSSRFGuardedClient returns an *http.Client whose transport uses
// ssrfGuardDialer. Pass this to WithHTTPClient on a Verifier that fetches JWKS
// from user-registered (remote_application) issuers to prevent SSRF via crafted
// jwks_uri values including DNS-rebinding attacks.
func NewSSRFGuardedClient() *http.Client {
	return &http.Client{
		Timeout: DefaultOutboundTimeout,
		Transport: &http.Transport{
			DialContext:           ssrfGuardDialer,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
		},
	}
}
