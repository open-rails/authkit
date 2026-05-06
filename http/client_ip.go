package authhttp

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ClientIPFunc determines the client IP used for rate limiting and auditing.
//
// Returning an empty string means "unknown" and causes rate limiting to fail open.
type ClientIPFunc func(r *http.Request) string

// DefaultClientIP returns a conservative client IP strategy:
//   - If RemoteAddr is a public IP, use it.
//   - If RemoteAddr is private/loopback/etc, return "" (fail open) so we don't accidentally
//     rate-limit a reverse proxy/ingress as a single client.
//
// Hosts behind proxies should configure a forwarded-header strategy with a trusted proxy list.
func DefaultClientIP() ClientIPFunc {
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

// ClientIPFromForwardedHeaders trusts CF-Connecting-IP and X-Forwarded-For only when the
// immediate peer (RemoteAddr) is in trustedProxies. Otherwise it falls back to DefaultClientIP behavior.
func ClientIPFromForwardedHeaders(trustedProxies []netip.Prefix) ClientIPFunc {
	return func(r *http.Request) string {
		peer := remoteIP(r)
		if peer == "" {
			return ""
		}
		peerAddr, err := netip.ParseAddr(peer)
		if err != nil {
			return ""
		}
		trusted := false
		for _, p := range trustedProxies {
			if p.Contains(peerAddr) {
				trusted = true
				break
			}
		}
		if trusted {
			if v := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); v != "" {
				if a, err := netip.ParseAddr(v); err == nil && isPublicAddr(a) {
					return a.String()
				}
			}
			if v := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); v != "" {
				// XFF is a comma-separated list; left-most is the original client.
				if i := strings.IndexByte(v, ','); i >= 0 {
					v = v[:i]
				}
				v = strings.TrimSpace(v)
				if a, err := netip.ParseAddr(v); err == nil && isPublicAddr(a) {
					return a.String()
				}
			}
		}
		// Fallback: only rate limit when peer is public.
		if isPublicAddr(peerAddr) {
			return peerAddr.String()
		}
		return ""
	}
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
