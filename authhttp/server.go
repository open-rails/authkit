package authhttp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/verify"

	memorylimiter "github.com/open-rails/authkit/ratelimit/memory"
	redislimiter "github.com/open-rails/authkit/ratelimit/redis"
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

// New assembles a local HTTP transport inside HTTPConfiguration.BuildHTTP.
// Applications normally set authkit.Config.HTTP instead. Runtime and portable
// Clients deliberately do not implement HTTPBackend.
func New(client Backend, hcfg Config) (*Service, error) {
	if client == nil {
		return nil, errors.New("authkit: authhttp.New requires an engine backend")
	}
	if err := hcfg.Validate(); err != nil {
		return nil, err
	}
	coreSvc := client
	cfg := coreSvc.Settings()

	s := &Service{
		dpopRequestURL:    hcfg.DPoPRequestURL,
		svc:               coreSvc,
		settings:          cfg,
		clientIP:          DefaultClientIP(),
		clientIPExplicit:  hcfg.ClientIP != nil,
		directPeerIP:      hcfg.DirectPeerIP,
		documentProviders: hcfg.Documents,
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

	verOpts := []verify.VerifierOption{
		verify.WithSkew(5 * time.Second),
		verify.WithAPIKeyPrefix(cfg.APIKeyPrefix),
		verify.WithRemoteApplicationAudiences(cfg.ExpectedAudiences...),
		// #240: wire the documented per-request forced-2FA-enrollment gate from
		// the host's TwoFactor policy. Required mode challenges every existing
		// un-enrolled user on their next request, not just at mint time.
		verify.WithRequireMFAEnrollment(cfg.RequireMFAEnrollment),
	}
	// SSRF guard on JWKS fetches. Applications.AllowPrivateNetworkJWKS is the
	// local-federation carve-out (#257): loopback/private JWKS the guarded
	// dialer would refuse.
	if !cfg.AllowPrivateNetworkJWKS {
		verOpts = append(verOpts, verify.WithSSRFGuard())
	}
	ver := verify.NewVerifier(verOpts...)
	if err := ver.AddIssuer(cfg.Issuer, cfg.ExpectedAudiences, verify.IssuerOptions{
		PublicKeys: coreSvc.PublicKeysByKID,
		IsLocal:    true,
	}); err != nil {
		return nil, err
	}
	ver.WithService(coreSvc).WithLiveness(coreSvc).WithPermissionChecker(coreSvc, cfg.Issuer)
	s.verifier = ver

	providers, err := providerRegistry(cfg.Providers, cfg.AccountIssuers)
	if err != nil {
		return nil, err
	}
	if err := requireHTTPSForFormPost(providers, cfg.FrontendBaseURL); err != nil {
		return nil, err
	}
	s.providers = providers

	// #243: derive the 2FA-enrollment allowlist from the route registry (single
	// source of truth — RouteSpec.MFAEnrollmentExempt) instead of a hand-
	// maintained suffix list, so a renamed/added enroll route can't silently
	// drift from the gate. Must run after every field APIRoutes reads is set.
	ver.SetMFAEnrollmentExemptPaths(mfaEnrollmentExemptPaths(s.APIRoutes()))

	if err := s.validate(cfg); err != nil {
		return nil, err
	}
	// Config.Validate guarantees at most one limiter choice.
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
			slog.Warn("authkit: Redis is optional but not configured; rate limits are per-process, so each replica counts separately. Set authhttp.Config.Redis when running more than one replica")
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
	// #260: the published-document surface is never public and never dead
	// config. Providers with no authorized readers would mount a route that
	// 401s everyone; readers with no providers declare a surface that does
	// not exist. Both refuse at construction.
	if len(s.documentProviders) > 0 && len(cfg.Documents.Readers) == 0 {
		return fmt.Errorf("authkit: authhttp.Config.Documents providers are wired but Config.Documents.Readers is empty — publication is never public; declare which remote applications may read")
	}
	if len(s.documentProviders) == 0 && len(cfg.Documents.Readers) > 0 {
		return fmt.Errorf("authkit: Config.Documents.Readers is set but no document providers are wired — set authhttp.Config.Documents or drop the dead config")
	}
	// #277: the delegated mint route never runs without its host authorizer,
	// and an authorizer with no route is dead wiring. Both refuse at construction.
	if len(cfg.Delegated.Audiences) > 0 && s.svc.DelegationAuthorizer() == nil {
		return fmt.Errorf("authkit: Config.Delegated.Audiences is set but no delegation authorizer is wired — set authkit.Deps.DelegatedAuthorization")
	}
	if len(cfg.Delegated.Audiences) == 0 && s.svc.DelegationAuthorizer() != nil {
		return fmt.Errorf("authkit: Deps.DelegatedAuthorization is wired but Config.Delegated.Audiences is empty — the mint route is disabled; drop the dead wiring or declare audiences")
	}
	seenDocumentTypes := make(map[string]bool, len(s.documentProviders))
	for _, p := range s.documentProviders {
		ref := p.Reference()
		if err := ref.Validate(); err != nil {
			return fmt.Errorf("authkit: document provider has an invalid reference %+v: %w", ref, err)
		}
		if seenDocumentTypes[ref.Type] {
			return fmt.Errorf("authkit: authhttp.Config.Documents has two providers for document type %q", ref.Type)
		}
		seenDocumentTypes[ref.Type] = true
	}
	return nil
}
