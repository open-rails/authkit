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
		if inPrefixes(peerAddr, trustedProxies) {
			// CF-Connecting-IP is a single value set by Cloudflare itself (not a
			// client-appendable list), so it is safe to trust when the peer is one
			// of our proxies.
			if v := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); v != "" {
				if a, err := netip.ParseAddr(v); err == nil && isPublicAddr(a) {
					return a.String()
				}
			}
			// X-Forwarded-For is a comma-separated chain "client, proxy1, ..., lastProxy".
			// The LEFT-most entry is supplied by the client and is therefore
			// spoofable — trusting it lets an attacker rotate their per-IP
			// rate-limit key at will. Walk RIGHT-to-LEFT instead (entries closest
			// to us are appended by infrastructure we control and are the most
			// trustworthy) and return the first hop that is NOT one of our own
			// trusted proxies (AK security audit F6).
			if v := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); v != "" {
				parts := strings.Split(v, ",")
				for i := len(parts) - 1; i >= 0; i-- {
					a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
					if err != nil {
						continue
					}
					if inPrefixes(a, trustedProxies) {
						continue // our own proxy hop; keep walking left
					}
					if isPublicAddr(a) {
						return a.String()
					}
					// First non-trusted hop is private/reserved: stop rather than
					// falling through to even-more-spoofable left entries.
					break
				}
			}
		}
		// Fallback to the immediate peer. This keeps rate limiting active even
		// if the peer is private and no trusted forwarded header is present.
		return peerAddr.String()
	}
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
