package authhttp

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/authprovider"
	core "github.com/open-rails/authkit/core"
	oidckit "github.com/open-rails/authkit/oidc"
	"github.com/open-rails/authkit/ratelimit"
	memorylimiter "github.com/open-rails/authkit/ratelimit/memory"
	memorystore "github.com/open-rails/authkit/storage/memory"
	redisstore "github.com/open-rails/authkit/storage/redis"
	"github.com/redis/go-redis/v9"
)

// Service wraps core.Service with net/http mounting helpers.
type Service struct {
	svc           *core.Service
	verifier      *Verifier
	rd            *redis.Client
	rl            RateLimiter
	clientIP      ClientIPFunc
	errorLogger   func(context.Context, InternalErrorEvent)
	oidcProviders map[string]oidckit.RPConfig
	providers     map[string]authprovider.Provider
	memStateCache oidckit.StateCache
	solanaDomain  string // Domain for SIWS messages (optional, derived from request if empty)
	langCfg       *LanguageConfig
	authlogr      core.AuthEventLogReader
}

func (s *Service) rateLimited(w http.ResponseWriter, r *http.Request, bucket string) bool {
	result := s.allowResult(r, bucket)
	if result.Allowed {
		return false
	}
	if result.Availability != nil {
		tooManyAvailability(w, *result.Availability, "rate_limited")
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
		tooManyAvailability(w, *result.Availability, "rate_limited")
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

// NewService constructs a core.Service and wraps it for net/http mounting.
// Returns an error if the core service fails to initialize (e.g., missing keys in production).
func NewService(cfg core.Config) (*Service, error) {
	coreSvc, err := core.NewFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	// Default to in-memory ephemeral store for dev/single-instance use.
	coreSvc = coreSvc.WithEphemeralStore(memorystore.NewKV(), core.EphemeralMemory)

	opts := coreSvc.Options()
	ver := NewVerifier(
		WithSkew(5*time.Second),
		WithOrgMode(opts.OrgMode),
		WithTokenPrefix(opts.TokenPrefix),
	)
	_ = ver.AddIssuer(opts.Issuer, opts.ExpectedAudiences, IssuerOptions{
		RawKeys: coreSvc.PublicKeysByKID(),
	})
	ver.WithService(coreSvc)

	s := &Service{
		svc:           coreSvc,
		verifier:      ver,
		oidcProviders: cfg.Providers,
		providers:     cfg.ProviderDescriptors,
		memStateCache: memorystore.NewStateCache(15 * time.Minute),
		rl:            memorylimiter.New(ToMemoryLimits(DefaultRateLimits())),
		clientIP:      DefaultClientIP(),
	}
	return s, nil
}

func (s *Service) WithPostgres(pg *pgxpool.Pool) *Service { s.svc = s.svc.WithPostgres(pg); return s }
func (s *Service) WithEntitlements(p core.EntitlementsProvider) *Service {
	s.svc = s.svc.WithEntitlements(p)
	return s
}
func (s *Service) WithRedis(rd *redis.Client) *Service {
	s.rd = rd
	if rd != nil {
		s.svc = s.svc.WithEphemeralStore(redisstore.NewKV(rd), core.EphemeralRedis)
	}
	return s
}
func (s *Service) WithRateLimiter(rl RateLimiter) *Service { s.rl = rl; return s }
func (s *Service) DisableRateLimiter() *Service            { s.rl = nil; return s }
func (s *Service) WithClientIPFunc(fn ClientIPFunc) *Service {
	if fn == nil {
		s.clientIP = DefaultClientIP()
		return s
	}
	s.clientIP = fn
	return s
}
func (s *Service) WithEmailSender(es core.EmailSender) *Service {
	s.svc = s.svc.WithEmailSender(es)
	return s
}
func (s *Service) WithSMSSender(sender core.SMSSender) *Service {
	s.svc = s.svc.WithSMSSender(sender)
	return s
}
func (s *Service) WithLanguageConfig(cfg LanguageConfig) *Service {
	s.langCfg = &cfg
	return s
}
func (s *Service) WithErrorLogger(fn func(context.Context, InternalErrorEvent)) *Service {
	s.errorLogger = fn
	return s
}
func (s *Service) WithAuthLogger(l core.AuthEventLogger) *Service {
	s.svc = s.svc.WithAuthLogger(l)
	return s
}
func (s *Service) WithAuthLogReader(r core.AuthEventLogReader) *Service {
	s.authlogr = r
	return s
}
func (s *Service) WithEphemeralStore(store core.EphemeralStore, mode core.EphemeralMode) *Service {
	s.svc = s.svc.WithEphemeralStore(store, mode)
	return s
}

// WithSolanaDomain sets the domain used in SIWS sign-in messages.
// If not set, the domain is derived from the request Origin or Host header.
func (s *Service) WithSolanaDomain(domain string) *Service {
	s.solanaDomain = domain
	return s
}

func (s *Service) Core() *core.Service { return s.svc }
func (s *Service) Verifier() *Verifier { return s.verifier }

// publicRegistrationDisabled reports whether public user self-registration /
// auto-registration is turned off for this service.
func (s *Service) publicRegistrationDisabled() bool {
	if s == nil || s.svc == nil {
		return false
	}
	return s.svc.Options().PublicRegistrationDisabled
}

// publicOrgManagementDisabled reports whether the public org onboarding /
// management HTTP routes are turned off for this service.
func (s *Service) publicOrgManagementDisabled() bool {
	if s == nil || s.svc == nil {
		return false
	}
	return s.svc.Options().PublicOrgManagementDisabled
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
