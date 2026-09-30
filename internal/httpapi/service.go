package httpapi

import (
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/open-rails/authkit/internal/authflow"

	"github.com/open-rails/authkit/provider"
)

// Service wraps the internal AuthKit engine with net/http mounting helpers.
type Service struct {
	dpopRequestURL      func(*http.Request) string
	svc                 Backend
	settings            authflow.Settings
	rl                  RateLimiter
	closers             []func() // background work stopped by Close (#305)
	clientIP            ClientIPFunc
	clientIPExplicit    bool                         // Config.ClientIP: host owns the strategy; proxy sets are not composed
	directPeerIP        bool                         // Config.DirectPeerIP: host asserts no proxy in front (ak#299)
	undeclaredProxyOnce sync.Once                    // one-shot tripwire: private peer carrying forwarded headers
	unknownAddressOnce  sync.Once                    // one-shot tripwire: no client address at all
	trustedProxies      []netip.Prefix               // Config.TrustedProxies: X-Forwarded-For walk
	cloudflareProxies   []netip.Prefix               // Config.CloudflareProxies: + CF-Connecting-IP fallback
	providers           map[string]provider.Provider // validated, keyed by Name()
	langCfg             *LanguageConfig
}

// limiterErrorResult is the verdict when the limiter's backend fails: refused,
// unless the bucket guards no secret (bucket.failOpen).
func limiterErrorResult(name string) RateLimitResult {
	return RateLimitResult{Allowed: buckets[name].failOpen}
}

func (s *Service) rateLimited(w http.ResponseWriter, r *http.Request, bucket string) bool {
	result := s.allowResult(r, bucket)
	if result.Allowed {
		return false
	}
	if result.Availability != nil {
		tooManyAvailability(w, *result.Availability)
		return true
	}
	tooMany(w, result.RetryAfter)
	return true
}

// rateLimitedByIdentifier checks an additional per-identifier key for the given
// bucket, on top of the route's per-IP check. Use it only where the secret space
// is small (one-time codes) or to stop one address being flooded with messages;
// never for passwords, where it would let strangers lock accounts out.
//
// identifier should be normalised (lowercased / trimmed) before being passed in.
// An empty identifier is a no-op (returns false).
func (s *Service) rateLimitedByIdentifier(w http.ResponseWriter, r *http.Request, bucket, identifier string) bool {
	if strings.TrimSpace(identifier) == "" {
		return false
	}
	// Build and check the per-identifier key (separate from the IP key).
	idKey := bucket + ":id:" + strings.ToLower(strings.TrimSpace(identifier))
	result := s.allowResultForKey(bucket, idKey)
	if result.Allowed {
		return false
	}
	if result.Availability != nil {
		tooManyAvailability(w, *result.Availability)
		return true
	}
	tooMany(w, result.RetryAfter)
	return true
}

// allowResultForKey is like allowResult but accepts an explicit key instead of deriving one from
// the request IP.  Used by rateLimitedByIdentifier to check a second, identifier-scoped key.
func (s *Service) allowResultForKey(bucket, key string) RateLimitResult {
	if s == nil || s.rl == nil {
		return RateLimitResult{Allowed: true}
	}
	if rl, ok := s.rl.(RateLimiterWithResult); ok {
		result, err := rl.AllowNamedResult(bucket, key)
		if err != nil {
			return limiterErrorResult(bucket)
		}
		availability := availabilityFromRateLimit(bucket, result, time.Now())
		return RateLimitResult{Allowed: result.Allowed, RetryAfter: result.RetryAfter, Availability: &availability}
	}
	ok, err := s.rl.AllowNamed(bucket, key)
	if err != nil {
		return limiterErrorResult(bucket)
	}
	return RateLimitResult{Allowed: ok}
}

func (s *Service) allowResult(r *http.Request, bucket string) RateLimitResult {
	if s == nil || s.rl == nil {
		return RateLimitResult{Allowed: true}
	}
	ip := strings.TrimSpace(s.requestIP(r))
	if ip == "" {
		// Never exempt: every request without an address shares one budget.
		s.unknownAddressOnce.Do(func() {
			slog.Default().Warn("authkit: a request has no client address, so every such request shares one rate-limit budget; declare what sits in front of AuthKit (HTTPConfig.TrustedProxies, CloudflareProxies, DirectPeerIP or ClientIP)")
		})
		return s.allowResultForKey(bucket, bucket+":ip:unknown")
	}
	s.undeclaredProxyTripwire(r, ip)
	return s.allowResultForKey(bucket, bucket+":ip:"+rateLimitAddress(ip))
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

// SMSAvailable reports whether phone-based flows should be offered (a sender is
// configured and, if checked, found able to deliver).
func (s *Service) SMSAvailable() bool { return s.svc.SMSAvailable() }

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
