package authhttp

import (
	"context"
	"github.com/open-rails/authkit/verify"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/open-rails/authkit/authprovider"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/internal/siws"
	memorystore "github.com/open-rails/authkit/internal/storage/memory"
	redisstore "github.com/open-rails/authkit/internal/storage/redis"
	"github.com/open-rails/authkit/oidckit"
	"github.com/open-rails/authkit/ratelimit"
	"github.com/redis/go-redis/v9"
)

// Service wraps the internal AuthKit engine with net/http mounting helpers.
type Service struct {
	svc                 *authcore.Service
	verifier            *verify.Verifier
	rd                  *redis.Client
	rl                  RateLimiter
	rlExplicit          bool                       // host set/disabled the limiter via WithRateLimiter/WithoutRateLimiter
	rlOverrides         map[string]ratelimit.Limit // WithRateLimitOverrides: merged onto DefaultRateLimits (#242)
	clientIP            ClientIPFunc
	trustedProxyErr     error // deferred WithTrustedProxies CIDR parse error, surfaced by NewServer
	authProvidersByName map[string]authprovider.Provider
	oidcMgr             *oidckit.Manager
	oidcMgrOnce         sync.Once
	memStateCache       oidckit.StateCache
	memSIWSCache        siws.ChallengeCache
	langCfg             *LanguageConfig
}

// failClosedBuckets are the credential-VERIFICATION endpoints where the secret
// being checked is low-entropy (a password, or a short numeric code) and a single
// unthrottled window is enough to brute-force it. For these, if the rate limiter
// cannot be consulted because of a BACKEND ERROR (e.g. a Redis outage), the
// request is DENIED (fail closed) rather than allowed — losing the limiter must
// not silently remove the only online brute-force defense (AK2-AUTH-05). Every
// other bucket keeps failing open, so a limiter outage degrades availability for
// the affected endpoint rather than taking down the whole auth surface.
//
// Note: this applies only to the limiter-ERROR path. A deliberately absent limiter
// (WithoutRateLimiter / s.rl == nil) is a configuration choice, not an outage, and
// continues to fail open — denying every login because a host opted out of rate
// limiting would be the wrong default.
var failClosedBuckets = map[string]struct{}{
	RL2FAVerify:              {},
	RLPasswordLogin:          {},
	RLPasswordResetConfirm:   {},
	RLEmailVerifyConfirm:     {},
	RLPhoneVerifyConfirm:     {},
	RLUserEmailChangeConfirm: {},
	RLUserPhoneChangeConfirm: {},
}

// limiterErrorResult is the verdict when the rate limiter returns a backend error.
// It fails CLOSED (denies) for the brute-force-sensitive verification buckets and
// open for everything else.
func limiterErrorResult(bucket string) RateLimitResult {
	if _, failClosed := failClosedBuckets[bucket]; failClosed {
		return RateLimitResult{Allowed: false}
	}
	return RateLimitResult{Allowed: true}
}

func (s *Service) rateLimited(w http.ResponseWriter, r *http.Request, bucket string) bool {
	result := s.allowResult(r, bucket)
	if result.Allowed {
		return false
	}
	if result.Availability != nil {
		tooManyAvailability(w, *result.Availability, ErrRateLimited)
		return true
	}
	tooMany(w, result.RetryAfter)
	return true
}

// rateLimitedByIdentifier checks an additional per-identifier key for the given bucket.
// It is designed to be called *after* the caller has already run s.rateLimited (IP check).
// Checking a second key closes the distributed-brute-force gap where many IPs each get
// their own per-IP budget against the same account or email address.
//
// identifier should be normalised (lowercased / trimmed) before being passed in.
// An empty identifier is a no-op (returns false).
func (s *Service) rateLimitedByIdentifier(w http.ResponseWriter, r *http.Request, bucket, identifier string) bool {
	if strings.TrimSpace(identifier) == "" {
		return false
	}
	// Build and check the per-identifier key (separate from the IP key).
	idKey := "auth:" + bucket + ":id:" + strings.ToLower(strings.TrimSpace(identifier))
	result := s.allowResultForKey(bucket, idKey)
	if result.Allowed {
		return false
	}
	if result.Availability != nil {
		tooManyAvailability(w, *result.Availability, ErrRateLimited)
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
	ipFn := s.clientIP
	if ipFn == nil {
		ipFn = DefaultClientIP()
	}
	ip := ipFn(r)
	if strings.TrimSpace(ip) == "" {
		return RateLimitResult{Allowed: true}
	}
	return s.allowResultForKey(bucket, "auth:"+bucket+":ip:"+ip)
}

// CheckSMSHealth probes (without sending an SMS) whether the configured sender
// can actually deliver, caching the result to gate phone-based flows. Returns
// the probe error (nil = healthy) so the host app can log it at startup.
func (s *Service) CheckSMSHealth(ctx context.Context) error { return s.svc.CheckSMSHealth(ctx) }

// SMSHealthy reports the last CheckSMSHealth result (true until a check runs).
func (s *Service) SMSHealthy() bool { return s.svc.SMSHealthy() }

// SMSHealthReason returns why SMS was last found unhealthy, if any.
func (s *Service) SMSHealthReason() string { return s.svc.SMSHealthReason() }

// SMSAvailable reports whether phone-based flows should be offered (a sender is
// configured and, if checked, found able to deliver).
func (s *Service) SMSAvailable() bool { return s.svc.SMSAvailable() }

// Verifier returns the server's token verifier. The embedder-facing client (for
// provisioning/minting/management) is the *embedded.Client the host built and
// passed to NewServer — code against authkit.Client to stay backend-agnostic
// across the embedded↔standalone swap (#138); the server no longer vends it
// (client-first, #142).
func (s *Service) Verifier() *verify.Verifier { return s.verifier }

// publicRegistrationDisabled reports whether public user self-registration /
// auto-registration is turned off for this service.
func (s *Service) publicRegistrationDisabled() bool {
	if s == nil || s.svc == nil {
		return false
	}
	return !s.svc.PublicNativeUserRegistrationEnabled()
}

func (s *Service) stateCache() oidckit.StateCache {
	if s.rd != nil {
		return redisstore.NewStateCache(s.rd, "auth:oidc:state:", 0)
	}
	if s.memStateCache == nil {
		s.memStateCache = memorystore.NewStateCache(15 * time.Minute)
	}
	return s.memStateCache
}
