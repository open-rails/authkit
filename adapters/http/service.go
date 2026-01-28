package authhttp

import (
	"net/http"
	"strings"
	"time"

	core "github.com/PaulFidika/authkit/core"
	oidckit "github.com/PaulFidika/authkit/oidc"
	memorylimiter "github.com/PaulFidika/authkit/ratelimit/memory"
	memorystore "github.com/PaulFidika/authkit/storage/memory"
	redisstore "github.com/PaulFidika/authkit/storage/redis"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// Service wraps core.Service with net/http mounting helpers.
type Service struct {
	svc           *core.Service
	rd            *redis.Client
	rl            RateLimiter
	clientIP      ClientIPFunc
	oidcProviders map[string]oidckit.RPConfig
	solanaDomain  string // Domain for SIWS messages (optional, derived from request if empty)
	langCfg       *LanguageConfig
}

func (s *Service) allow(r *http.Request, bucket string) bool {
	if s == nil {
		return true
	}
	if s.rl == nil {
		return true
	}
	ipFn := s.clientIP
	if ipFn == nil {
		ipFn = DefaultClientIP()
	}
	ip := ipFn(r)
	if strings.TrimSpace(ip) == "" {
		return true
	}
	key := "auth:" + bucket + ":ip:" + ip
	ok, err := s.rl.AllowNamed(bucket, key)
	if err != nil {
		return true
	}
	return ok
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
	s := &Service{
		svc:           coreSvc,
		oidcProviders: cfg.Providers,
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
func (s *Service) WithAuthLogger(l core.AuthEventLogger) *Service {
	s.svc = s.svc.WithAuthLogger(l)
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

func (s *Service) stateCache() oidckit.StateCache {
	if s.rd != nil {
		return redisstore.NewStateCache(s.rd, "auth:oidc:state:", 0)
	}
	return memorystore.NewStateCache(15 * time.Minute)
}
