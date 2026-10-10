package httpapi

import (
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ratelimit"

	"github.com/open-rails/authkit/provider"
)

// Service wraps the internal AuthKit engine with net/http mounting helpers.
type Service struct {
	svc                 Backend
	cfg                 config.Config     // normalized
	http                config.HTTPConfig // *cfg.HTTP
	wrap                func(iam.Route, http.Handler) http.Handler
	rl                  ratelimit.Limiter
	clientIP            ClientIPFunc
	clientIPExplicit    bool                         // Deps.ClientIP: host owns the strategy; proxy sets are not composed
	directPeerIP        bool                         // Config.DirectPeerIP: host asserts no proxy in front (ak#299)
	undeclaredProxyOnce sync.Once                    // one-shot tripwire: private peer carrying forwarded headers
	unknownAddressOnce  sync.Once                    // one-shot tripwire: no client address at all
	trustedProxies      []netip.Prefix               // Config.TrustedProxies: X-Forwarded-For walk
	cloudflareProxies   []netip.Prefix               // Config.CloudflareProxies: + CF-Connecting-IP fallback
	providers           map[string]provider.Provider // validated, keyed by Name()
}

// rateLimited spends one request of bucket's budget for the client address
// and writes the 429 once it is spent.
func (s *Service) rateLimited(w http.ResponseWriter, r *http.Request, bucket string) bool {
	return s.limited(w, r, bucket, bucket+":ip:"+s.addressKey(r))
}

// rateLimitedByIdentifier checks an additional per-identifier key for the given
// bucket, on top of the route's per-IP check. Use it only where the secret space
// is small (one-time codes) or to stop one address being flooded with messages;
// never for passwords, where it would let strangers lock accounts out.
//
// An empty identifier is a no-op (returns false).
func (s *Service) rateLimitedByIdentifier(w http.ResponseWriter, r *http.Request, bucket, identifier string) bool {
	identifier = strings.ToLower(strings.TrimSpace(identifier))
	if identifier == "" {
		return false
	}
	return s.limited(w, r, bucket, bucket+":id:"+identifier)
}

// limited spends one request of key's budget in bucket; once it is spent it
// writes the 429 with Retry-After and the budget. When no store can decide,
// the request is refused 503.
func (s *Service) limited(w http.ResponseWriter, r *http.Request, bucket, key string) bool {
	result, err := s.rl.Allow(r.Context(), bucket, key)
	if err != nil {
		fail(w, errmodel.CodeServerBusy, errmodel.WithDetails(errmodel.RetryAfter{RetryAfterSeconds: 1}))
		return true
	}
	if result.Allowed {
		return false
	}
	tooMany(w, availabilityFromRateLimit(bucket, result, time.Now()))
	return true
}

// addressKey is the client address a budget is kept for. Requests without
// one share a single budget: never exempt.
func (s *Service) addressKey(r *http.Request) string {
	ip := strings.TrimSpace(s.requestIP(r))
	if ip == "" {
		s.unknownAddressOnce.Do(func() {
			slog.Default().Warn("authkit: a request has no client address, so every such request shares one rate-limit budget; declare what sits in front of AuthKit (HTTPConfig.TrustedProxies, CloudflareProxies, DirectPeerIP or ClientIP)")
		})
		return "unknown"
	}
	s.undeclaredProxyTripwire(r, ip)
	return rateLimitAddress(ip)
}

// rateLimitAddress keys IPv6 clients by /64: one subscriber usually holds a
// whole /64, so per-/128 buckets would hand them 2^64 budgets.
func rateLimitAddress(ip string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is4() {
		return a.String()
	}
	return netip.PrefixFrom(a.WithZone(""), 64).Masked().String()
}

// undeclaredProxyTripwire logs once per process when the rate-limit key is a
// private/loopback peer that carries forwarded headers: a proxy the host did not
// declare is in front, so every client shares that peer's bucket (ak#299).
func (s *Service) undeclaredProxyTripwire(r *http.Request, ip string) {
	if r.Header.Get("X-Forwarded-For") == "" && r.Header.Get("CF-Connecting-IP") == "" {
		return
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || isPublicAddr(a) {
		return
	}
	s.undeclaredProxyOnce.Do(func() {
		slog.Default().Error("authkit: rate-limit key is a private peer that carries forwarded headers; an undeclared proxy is in front and every client shares one bucket; declare it in HTTPConfig.TrustedProxies or CloudflareProxies",
			slog.String("peer", ip))
	})
}

// Backend returns the engine the service drives.
func (s *Service) Backend() Backend { return s.svc }

// publicRegistrationDisabled reports whether public user self-registration /
// auto-registration is turned off for this service.
func (s *Service) publicRegistrationDisabled() bool {
	if s == nil || s.svc == nil {
		return false
	}
	return !s.svc.PublicNativeUserRegistrationEnabled()
}
