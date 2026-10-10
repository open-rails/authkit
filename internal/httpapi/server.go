package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/ratelimit"

	memorylimiter "github.com/open-rails/authkit/internal/ratelimit/memory"
	redislimiter "github.com/open-rails/authkit/internal/ratelimit/redis"
)

// Close stops the background work New started: the in-process limiter sweep.
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

// New assembles the HTTP layer over the engine, which also authenticates its
// requests, from the normalized configuration. authkit.New is the only
// production caller.
func New(client Backend, cfg config.Config, deps config.Deps) (*Service, error) {
	if client == nil || cfg.HTTP == nil {
		return nil, errors.New("authkit: httpapi.New requires an engine backend and Config.HTTP")
	}
	h := *cfg.HTTP
	s := &Service{
		svc:              client,
		cfg:              cfg,
		http:             h,
		clientIP:         DefaultClientIP(),
		clientIPExplicit: deps.ClientIP != nil,
		directPeerIP:     h.DirectPeerIP,
		wrap:             deps.Wrap,
	}
	s.trustedProxies, _ = config.ParseCIDRs("trusted proxy", h.TrustedProxies)
	s.cloudflareProxies, _ = config.ParseCIDRs("Cloudflare proxy", h.CloudflareProxies)
	switch {
	case deps.ClientIP != nil:
		s.clientIP = deps.ClientIP
	case len(s.trustedProxies) > 0 || len(s.cloudflareProxies) > 0:
		s.clientIP = ClientIPFromForwardedHeaders(s.trustedProxies, s.cloudflareProxies)
	}

	providers, err := providerRegistry(deps.Providers, cfg.Token.AccountIssuers)
	if err != nil {
		return nil, err
	}
	if err := requireHTTPSForFormPost(providers, cfg.Frontend.BaseURL); err != nil {
		return nil, err
	}
	s.providers = providers

	limits := DefaultRateLimits()
	for bucket, lim := range h.RateLimits {
		if _, ok := limits[bucket]; !ok {
			return nil, fmt.Errorf("authkit: RateLimits names unknown bucket %q", bucket)
		}
		limits[bucket] = lim
	}
	var rl interface {
		ratelimit.Limiter
		StartCleanup(context.Context, time.Duration)
	}
	if deps.Redis != nil {
		rl, err = redislimiter.New(deps.Redis, limits, h.RedisKeyPrefix+"ratelimit:")
	} else {
		rl, err = memorylimiter.New(limits)
		slog.Warn("authkit: Redis not configured; rate limits are per-process, so each replica counts separately")
	}
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	rl.StartCleanup(ctx, time.Minute)
	s.closers = append(s.closers, cancel)
	s.rl = rl
	return s, nil
}
