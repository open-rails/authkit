package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/verify"

	memorylimiter "github.com/open-rails/authkit/internal/ratelimit/memory"
	redislimiter "github.com/open-rails/authkit/internal/ratelimit/redis"
)

// Close stops the background work New started: the memory limiter sweep.
// The engine and Redis client are borrowed and remain owned by the host.
// Idempotent; safe on a nil Service.
func (s *Service) Close() {
	if s == nil {
		return
	}
	for _, stop := range s.closers {
		stop()
	}
	s.closers = nil
}

// New assembles the HTTP layer over the engine and its verifier. authkit.New
// is the only production caller.
func New(client Backend, verifier *verify.Verifier, hcfg Config) (*Service, error) {
	if client == nil || verifier == nil {
		return nil, errors.New("authkit: httpapi.New requires an engine backend and its verifier")
	}
	if err := hcfg.Validate(); err != nil {
		return nil, err
	}
	coreSvc := client
	cfg := coreSvc.Settings()

	s := &Service{
		dpopRequestURL:   hcfg.DPoPRequestURL,
		svc:              coreSvc,
		settings:         cfg,
		verifier:         verifier,
		clientIP:         DefaultClientIP(),
		clientIPExplicit: hcfg.ClientIP != nil,
		directPeerIP:     hcfg.DirectPeerIP,
	}
	s.trustedProxies, _ = parseProxyCIDRs("trusted proxy", hcfg.TrustedProxies)
	s.cloudflareProxies, _ = parseProxyCIDRs("Cloudflare proxy", hcfg.CloudflareProxies)
	switch {
	case hcfg.ClientIP != nil:
		s.clientIP = hcfg.ClientIP
	case len(s.trustedProxies) > 0 || len(s.cloudflareProxies) > 0:
		s.clientIP = ClientIPFromForwardedHeaders(s.trustedProxies, s.cloudflareProxies)
	}
	if len(hcfg.Languages.Supported) > 0 || strings.TrimSpace(hcfg.Languages.Default) != "" {
		lc := hcfg.Languages
		s.langCfg = &lc
	}

	providers, err := providerRegistry(cfg.Providers, cfg.AccountIssuers)
	if err != nil {
		return nil, err
	}
	if err := requireHTTPSForFormPost(providers, cfg.FrontendBaseURL); err != nil {
		return nil, err
	}
	s.providers = providers

	if err := s.validate(cfg); err != nil {
		return nil, err
	}
	// Config.Validate refuses conflicting limiter choices.
	switch {
	case hcfg.Limiter != nil:
		s.rl = hcfg.Limiter
	case hcfg.DisableRateLimiting:
		s.rl = nil
	default:
		limits := DefaultRateLimits()
		for bucket, lim := range hcfg.RateLimits {
			limits[bucket] = lim
		}
		if hcfg.Redis != nil {
			prefix, err := redisKeyPrefix(hcfg.RedisKeyPrefix, cfg.Schema)
			if err != nil {
				return nil, err
			}
			rl, err := redislimiter.New(hcfg.Redis, limits, prefix+"ratelimit:")
			if err != nil {
				return nil, err
			}
			s.rl = rl
			slog.Info("authkit: rate limiter", "backend", "redis")
		} else {
			ml, err := memorylimiter.New(limits)
			if err != nil {
				return nil, err
			}
			ctx, cancel := context.WithCancel(context.Background())
			ml.StartCleanup(ctx, time.Minute)
			s.closers = append(s.closers, cancel)
			s.rl = ml
			slog.Warn("authkit: Redis not configured; rate limits are per-process, so each replica counts separately")
		}
	}
	return s, nil
}

// validate enforces the cross-layer dependency requirements for the configured
// feature set (Config.Validate covers the HTTP layer's own fields).
func (s *Service) validate(cfg authflow.Settings) error {
	// #212: the registration-verification policy must be satisfiable by a
	// configured delivery sender at CONSTRUCTION time. Fail here with an error
	// instead of panicking later when handlers are mounted.
	if err := s.svc.ValidateVerificationConfiguration(); err != nil {
		return err
	}
	// #277: the delegated mint route never runs without its host authorizer,
	// and an authorizer with no route is dead wiring. Both refuse at construction.
	if len(cfg.Delegated.Audiences) > 0 && s.svc.DelegationAuthorizer() == nil {
		return fmt.Errorf("authkit: Config.Delegated.Audiences is set but no delegation authorizer is wired — set authkit.Deps.DelegatedAuthorization")
	}
	if len(cfg.Delegated.Audiences) == 0 && s.svc.DelegationAuthorizer() != nil {
		return fmt.Errorf("authkit: Deps.DelegatedAuthorization is wired but Config.Delegated.Audiences is empty — the mint route is disabled; drop the dead wiring or declare audiences")
	}
	return nil
}
