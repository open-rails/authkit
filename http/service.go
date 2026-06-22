package authhttp

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/open-rails/authkit/authprovider"
	core "github.com/open-rails/authkit/core"
	oidckit "github.com/open-rails/authkit/oidc"
	"github.com/open-rails/authkit/ratelimit"
	memorystore "github.com/open-rails/authkit/storage/memory"
	redisstore "github.com/open-rails/authkit/storage/redis"
	"github.com/redis/go-redis/v9"
)

// Service wraps core.Service with net/http mounting helpers.
type Service struct {
	svc                 *core.Service
	verifier            *Verifier
	rd                  *redis.Client
	rl                  RateLimiter
	clientIP            ClientIPFunc
	errorLogger         func(context.Context, InternalErrorEvent)
	oidcProviders       map[string]oidckit.RPConfig
	providers           map[string]authprovider.Provider
	authProvidersByName map[string]authprovider.Provider
	oidcMgr             *oidckit.Manager
	oidcMgrOnce         sync.Once
	memStateCache       oidckit.StateCache
	solanaDomain        string // Domain for SIWS messages (optional, derived from request if empty)
	langCfg             *LanguageConfig
	authlogr            core.AuthEventLogReader
	// coreOpts accumulates core.Option values contributed by functional options
	// during NewServer; they are applied when the core service is built, then the
	// slice is cleared (transient, not retained past construction).
	coreOpts []core.Option

	// groupCanFn overrides the permission-group authorization predicate used by
	// the auto-generated group-management routes (#111). nil in production (the
	// default delegates to core.Service.Can); set only by handler tests that need
	// to gate without a database.
	groupCanFn func(r *http.Request, subjectID, persona, resourceID, perm string) (bool, error)
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
			return RateLimitResult{Allowed: true}
		}
		availability := availabilityFromRateLimit(bucket, result, time.Now())
		return RateLimitResult{Allowed: result.Allowed, RetryAfter: result.RetryAfter, Availability: &availability}
	}
	if rl, ok := s.rl.(RateLimiterWithRetryAfter); ok {
		allowed, retryAfter, err := rl.AllowNamedWithRetryAfter(bucket, key)
		if err != nil {
			return RateLimitResult{Allowed: true}
		}
		result := RateLimitResult{Allowed: allowed, RetryAfter: retryAfter}
		if !allowed {
			availability := availabilityFromRateLimit(bucket, ratelimit.Result{
				Allowed:    false,
				RetryAfter: retryAfter,
				Reason:     ratelimit.ReasonLimitExceeded,
			}, time.Now())
			result.Availability = &availability
		}
		return result
	}
	ok, err := s.rl.AllowNamed(bucket, key)
	if err != nil {
		return RateLimitResult{Allowed: true}
	}
	return RateLimitResult{Allowed: ok}
}

func (s *Service) allowResult(r *http.Request, bucket string) RateLimitResult {
	if s == nil {
		return RateLimitResult{Allowed: true}
	}
	if s.rl == nil {
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
	key := "auth:" + bucket + ":ip:" + ip
	if rl, ok := s.rl.(RateLimiterWithResult); ok {
		result, err := rl.AllowNamedResult(bucket, key)
		if err != nil {
			return RateLimitResult{Allowed: true}
		}
		availability := availabilityFromRateLimit(bucket, result, time.Now())
		return RateLimitResult{Allowed: result.Allowed, RetryAfter: result.RetryAfter, Availability: &availability}
	}
	if rl, ok := s.rl.(RateLimiterWithRetryAfter); ok {
		allowed, retryAfter, err := rl.AllowNamedWithRetryAfter(bucket, key)
		if err != nil {
			return RateLimitResult{Allowed: true}
		}
		result := RateLimitResult{Allowed: allowed, RetryAfter: retryAfter}
		if !allowed {
			availability := availabilityFromRateLimit(bucket, ratelimit.Result{
				Allowed:    false,
				RetryAfter: retryAfter,
				Reason:     ratelimit.ReasonLimitExceeded,
			}, time.Now())
			result.Availability = &availability
		}
		return result
	}
	ok, err := s.rl.AllowNamed(bucket, key)
	if err != nil {
		return RateLimitResult{Allowed: true}
	}
	return RateLimitResult{Allowed: ok}
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

func (s *Service) Core() *core.Service { return s.svc }
func (s *Service) Verifier() *Verifier { return s.verifier }

// SetEntitlementsProvider installs the entitlements provider on the underlying
// core service after construction. It is the sanctioned late-binding seam for
// the embedded-billing entitlements cycle (an embedded engine authenticates
// through this server's Verifier/Core yet also supplies the provider). Call it
// during wiring, before serving. See core.Service.SetEntitlementsProvider.
func (s *Service) SetEntitlementsProvider(p core.EntitlementsProvider) {
	s.svc.SetEntitlementsProvider(p)
}

// publicRegistrationDisabled reports whether public user self-registration /
// auto-registration is turned off for this service.
func (s *Service) publicRegistrationDisabled() bool {
	if s == nil || s.svc == nil {
		return false
	}
	return !s.svc.Options().PublicNativeUserRegistrationEnabled()
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
