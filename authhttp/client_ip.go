package authhttp

import (
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
)

// ClientIPFunc determines the client IP used for rate limiting and auditing.
//
// Returning an empty string means "unknown" and causes rate limiting to fail open.
type ClientIPFunc func(r *http.Request) string

// DefaultClientIP returns the immediate peer IP from RemoteAddr.
//
// This intentionally includes private and loopback peers so embedded/local
// deployments still get default rate-limit protection. Hosts behind reverse
// proxies should use ClientIPFromForwardedHeaders with trusted proxy CIDRs when
// they need the original public client IP instead of the proxy peer.
func DefaultClientIP() ClientIPFunc {
	return func(r *http.Request) string {
		return remoteIP(r)
	}
}

// PublicRemoteAddrClientIP returns the older conservative client IP strategy:
//   - If RemoteAddr is a public IP, use it.
//   - If RemoteAddr is private/loopback/etc, return "" (fail open) so we don't accidentally
//     rate-limit a reverse proxy/ingress as a single client.
func PublicRemoteAddrClientIP() ClientIPFunc {
	return func(r *http.Request) string {
		ip := remoteIP(r)
		if ip == "" {
			return ""
		}
		parsed, err := netip.ParseAddr(ip)
		if err != nil {
			return ""
		}
		if isPublicAddr(parsed) {
			return parsed.String()
		}
		return ""
	}
}

// ClientIPFromForwardedHeaders derives the client IP behind proxies the host
// declared. A peer inside trusted or cloudflare enables the right-to-left
// X-Forwarded-For walk (hops in either set are skipped as our own). Only a peer
// inside cloudflare may additionally be trusted for CF-Connecting-IP, and only
// as a fallback when X-Forwarded-For yields nothing: a generic reverse proxy
// forwards CF-Connecting-IP verbatim, so honouring it from any trusted peer let
// a client pick its own rate-limit key (ak#298). Any other peer resolves to
// itself.
//
// Hosts that pass a cloudflare set must also lock the origin down to Cloudflare
// ingress; otherwise a client that reaches the origin directly is its own peer
// and both headers are ignored, which is the safe outcome.
func ClientIPFromForwardedHeaders(trusted, cloudflare []netip.Prefix) ClientIPFunc {
	var disagreeOnce sync.Once
	return func(r *http.Request) string {
		peer := remoteIP(r)
		if peer == "" {
			return ""
		}
		peerAddr, err := netip.ParseAddr(peer)
		if err != nil {
			return ""
		}
		fromCloudflare := inPrefixes(peerAddr, cloudflare)
		if !fromCloudflare && !inPrefixes(peerAddr, trusted) {
			return peerAddr.String()
		}
		xff := forwardedForClient(r.Header.Get("X-Forwarded-For"), trusted, cloudflare)
		var cf netip.Addr
		if fromCloudflare {
			if a, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))); err == nil && isPublicAddr(a) {
				cf = a
			}
		}
		switch {
		case xff.IsValid():
			if cf.IsValid() && cf != xff {
				disagreeOnce.Do(func() {
					slog.Default().Warn("authkit: X-Forwarded-For and CF-Connecting-IP disagree; using X-Forwarded-For",
						slog.String("x_forwarded_for", xff.String()), slog.String("cf_connecting_ip", cf.String()))
				})
			}
			return xff.String()
		case cf.IsValid():
			return cf.String()
		}
		return peerAddr.String()
	}
}

// forwardedForClient walks X-Forwarded-For ("client, proxy1, ..., lastProxy")
// RIGHT-to-LEFT: entries closest to us were appended by infrastructure we
// declared, the left-most one is client-supplied and spoofable (AK audit F6).
// It returns the first hop that is not one of our own proxies, or an invalid
// Addr when that hop is not public or the header is absent.
func forwardedForClient(header string, trusted, cloudflare []netip.Prefix) netip.Addr {
	parts := strings.Split(header, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			continue
		}
		if inPrefixes(a, trusted) || inPrefixes(a, cloudflare) {
			continue
		}
		if isPublicAddr(a) {
			return a
		}
		break
	}
	return netip.Addr{}
}

// inPrefixes reports whether a is contained in any of the given CIDR prefixes.
func inPrefixes(a netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func remoteIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if r.RemoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	// If RemoteAddr is already just an IP without port.
	return r.RemoteAddr
}

func isPublicAddr(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalMulticast() || a.IsLinkLocalUnicast() {
		return false
	}
	if a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	return true
}
