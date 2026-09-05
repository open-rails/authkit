// Package netguard is the single outbound-network policy for AuthKit: the
// private/reserved address list, the resolve-then-dial SSRF guard, and the
// timeout-bounded HTTP client every package uses for fetches it does not fully
// control (JWKS, application documents, IdP endpoints).
package netguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// DefaultTimeout bounds AuthKit's outbound HTTP calls. A slow or hostile
// endpoint must never wedge a request goroutine, and single-flighted fetches
// (JWKS) would otherwise stall every concurrent waiter.
const DefaultTimeout = 30 * time.Second

var privateBlocks = parseBlocks(
	"0.0.0.0/8",          // unspecified / "this" network
	"10.0.0.0/8",         // RFC-1918 private
	"100.64.0.0/10",      // RFC-6598 carrier-grade NAT
	"127.0.0.0/8",        // loopback
	"169.254.0.0/16",     // link-local — AWS/GCP instance metadata
	"172.16.0.0/12",      // RFC-1918 private
	"192.168.0.0/16",     // RFC-1918 private
	"198.18.0.0/15",      // RFC-2544 benchmarking
	"198.51.100.0/24",    // RFC-5737 documentation
	"203.0.113.0/24",     // RFC-5737 documentation
	"240.0.0.0/4",        // reserved (class E)
	"255.255.255.255/32", // broadcast
	"::1/128",            // IPv6 loopback
	"fc00::/7",           // IPv6 unique local
	"fe80::/10",          // IPv6 link-local
	"::/128",             // IPv6 unspecified
)

func parseBlocks(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("netguard: bad CIDR literal " + cidr)
		}
		out = append(out, block)
	}
	return out
}

// IsPrivateIP reports whether ip is loopback, link-local, multicast,
// unspecified, or inside PrivateBlocks.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, block := range privateBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// IsInternalHostname reports whether host names a well-known internal target
// (localhost, cloud metadata aliases, Docker/Podman host-access names). It is
// a syntactic check for registration-time validation; the dialer's
// post-resolution IP check is the layer that catches everything else.
func IsInternalHostname(host string) bool {
	lower := strings.ToLower(strings.TrimSpace(host))
	switch {
	case lower == "localhost",
		strings.HasSuffix(lower, ".localhost"),
		lower == "metadata",
		lower == "metadata.google.internal",
		lower == "host.docker.internal",
		lower == "gateway.docker.internal",
		lower == "kubernetes.docker.internal",
		lower == "host-gateway",
		strings.HasSuffix(lower, ".docker.internal"),
		lower == "host.containers.internal",
		strings.HasSuffix(lower, ".containers.internal"):
		return true
	}
	return false
}

// Resolver is the DNS seam the guarded dialer resolves through.
// *net.Resolver satisfies it.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// DialFunc is the http.Transport.DialContext shape.
type DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error)

// DialerWith is Dialer with an explicit Resolver.
func DialerWith(r Resolver, allowPrivate bool) DialFunc {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if allowPrivate {
		return d.DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("netguard: bad address %q: %v", addr, err)
		}
		if ip := net.ParseIP(host); ip != nil {
			if IsPrivateIP(ip) {
				return nil, fmt.Errorf("netguard: %s is a private/reserved IP", ip)
			}
			return d.DialContext(ctx, network, addr)
		}
		ips, err := r.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("netguard: resolve %q: %v", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("netguard: %q resolved to no addresses", host)
		}
		for _, ip := range ips {
			if IsPrivateIP(ip.IP) {
				return nil, fmt.Errorf("netguard: %q resolves to private/reserved IP %s", host, ip.IP)
			}
		}
		return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}
}

// Transport returns an http.Transport wired to DialerWith(net.DefaultResolver, allowPrivate) with
// bounded handshake and header timeouts. A guarded transport never uses an
// egress proxy: the proxy would be dialed in place of the resolved target and
// the private-address check would no longer see the real destination.
func Transport(allowPrivate bool) *http.Transport {
	return TransportWith(net.DefaultResolver, allowPrivate)
}

// TransportWith is Transport with an explicit Resolver.
func TransportWith(r Resolver, allowPrivate bool) *http.Transport {
	t := &http.Transport{
		DialContext:           DialerWith(r, allowPrivate),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
	}
	if allowPrivate {
		t.Proxy = http.ProxyFromEnvironment
	}
	return t
}

// Client returns a timeout-bounded *http.Client over Transport(allowPrivate).
// timeout <= 0 uses DefaultTimeout.
func Client(timeout time.Duration, allowPrivate bool) *http.Client {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &http.Client{Timeout: timeout, Transport: Transport(allowPrivate)}
}
