package authhttp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/open-rails/authkit/verify"

	"github.com/open-rails/authkit/embedded"
	memorylimiter "github.com/open-rails/authkit/internal/ratelimit/memory"
	redislimiter "github.com/open-rails/authkit/internal/ratelimit/redis"
	memorystore "github.com/open-rails/authkit/internal/storage/memory"
)

// Close stops the background work New started (the in-memory limiter's sweep).
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

// New constructs the HTTP adapter over a client the host already built —
// client-first construction (#142). The host wires the engine and its
// dependencies on embedded.New; New takes only the HTTP layer's Config.
// Postgres is REQUIRED: the durable user/role and permission-group store has
// no in-memory fallback (#106), so the client must be Postgres-backed; pure
// token verification with no storage uses verify.NewVerifier instead.
//
// Construction fails (returns an error, never panics — #212) when the
// configuration cannot be served: Config.Validate refuses a missing client-IP
// posture or a bad CIDR, and the cross-layer checks refuse a "required"
// registration verification with no sender (Deps.Email / Deps.SMS), document
// providers without readers, and a delegated route without its authorizer.
//
// Redis is taken ONCE (#210): the engine's Redis client (Deps.Redis) also backs
// the HTTP layer's OIDC/SIWS state caches and rate limiter; Config.Redis is an
// override, not a requirement.
//
//	client, err := embedded.New(cfg, embedded.Deps{Postgres: pg, Redis: rdb, Email: mailer})
//	srv, err := authhttp.New(client, authhttp.Config{TrustedProxies: []string{"10.0.0.0/8"}})
func New(client *embedded.Client, hcfg Config) (*Service, error) {
	if client == nil || client.Postgres() == nil {
		return nil, errors.New("authkit: authhttp.New requires a Postgres-backed *embedded.Client (Postgres is mandatory)")
	}
	if err := hcfg.Validate(); err != nil {
		return nil, err
	}
	if err := probeMigrations(client); err != nil {
		return nil, err
	}
	coreSvc := client
	cfg := coreSvc.Config()

	s := &Service{
		svc:                coreSvc,
		rd:                 hcfg.Redis,
		clientIP:           DefaultClientIP(),
		clientIPExplicit:   hcfg.ClientIP != nil,
		directPeerIP:       hcfg.DirectPeerIP,
		memoryLimiterSweep: hcfg.memoryLimiterSweep,
		documentProviders:  hcfg.Documents,
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

	// #210: take Redis ONCE. Config.Redis overrides; otherwise the engine's
	// client backs the HTTP layer's OIDC/SIWS caches and rate limiter too — one
	// Redis instance, single source of truth, no split-brain ephemeral state.
	if s.rd == nil {
		s.rd = coreSvc.EphemeralRedisClient()
	}

	// AuthKit owns the rate-limit policy unless the host replaced or disabled
	// the limiter: Redis-backed when Redis is wired, so limits are shared
	// across instances; in-memory otherwise.
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
		if s.rd != nil {
			s.rl = redislimiter.New(s.rd, limits, coreSvc.RedisKeyPrefix()+"ratelimit:")
			slog.Info("authkit: rate limiter", "backend", "redis")
		} else {
			ml := memorylimiter.New(limits)
			sweep := s.memoryLimiterSweep
			if sweep <= 0 {
				sweep = time.Minute
			}
			ctx, cancel := context.WithCancel(context.Background())
			ml.StartCleanup(ctx, sweep)
			s.closers = append(s.closers, cancel)
			s.rl = ml
			slog.Info("authkit: rate limiter", "backend", "memory")
		}
	}

	verOpts := []verify.VerifierOption{
		verify.WithSkew(5 * time.Second),
		verify.WithAPIKeyPrefix(cfg.APIKeys.Prefix),
		verify.WithRemoteApplicationAudiences(cfg.Token.ExpectedAudiences...),
		// #240: wire the documented per-request forced-2FA-enrollment gate from
		// the host's TwoFactor policy. Required mode challenges every existing
		// un-enrolled user on their next request, not just at mint time.
		verify.WithRequireMFAEnrollment(cfg.TwoFactor.Mode == embedded.TwoFactorRequired),
	}
	// SSRF guard on JWKS fetches. Applications.AllowPrivateNetworkJWKS is the
	// local-federation carve-out (#257): loopback/private JWKS the guarded
	// dialer would refuse.
	if !cfg.Applications.AllowPrivateNetworkJWKS {
		verOpts = append(verOpts, verify.WithSSRFGuard())
	}
	ver := verify.NewVerifier(verOpts...)
	_ = ver.AddIssuer(cfg.Token.Issuer, cfg.Token.ExpectedAudiences, verify.IssuerOptions{
		RawKeys: coreSvc.PublicKeysByKID(),
		IsLocal: true,
	})
	ver.WithService(coreSvc)
	s.verifier = ver

	providers, err := providerRegistry(cfg.Identity.Providers)
	if err != nil {
		return nil, err
	}
	if err := requireHTTPSForFormPost(providers, cfg.Frontend.BaseURL); err != nil {
		return nil, err
	}
	s.providers = providers
	s.memStateCache = memorystore.NewStateCache(15 * time.Minute)
	s.memSIWSCache = memorystore.NewSIWSCache(15 * time.Minute)

	// #243: derive the 2FA-enrollment allowlist from the route registry (single
	// source of truth — RouteSpec.MFAEnrollmentExempt) instead of a hand-
	// maintained suffix list, so a renamed/added enroll route can't silently
	// drift from the gate. Must run after every field APIRoutes reads is set.
	ver.SetMFAEnrollmentExemptPaths(mfaEnrollmentExemptPaths(s.APIRoutes()))

	if err := s.validate(cfg); err != nil {
		return nil, err
	}
	return s, nil
}

// probeMigrations fails fast at construction when AuthKit's migrations were
// never run — a definitive "users table missing" beats a cryptic mid-request
// `relation "profiles.users" does not exist`. Fail-open on probe errors
// (connectivity, permissions): those surface elsewhere; only a definitive
// "table missing" fails construction.
func probeMigrations(client *embedded.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var exists bool
	err := client.Postgres().QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = $1 AND table_name = 'users')`,
		client.Schema(),
	).Scan(&exists)
	if err != nil || exists {
		return nil
	}
	return fmt.Errorf("authkit: schema %q has no users table — run AuthKit's migrations before constructing the server (authkitmigrate.New(pool, ...).Migrate(ctx))", client.Schema())
}

// validate enforces the cross-layer dependency requirements for the configured
// feature set (Config.Validate covers the HTTP layer's own fields).
func (s *Service) validate(cfg embedded.Config) error {
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
		return fmt.Errorf("authkit: Config.Delegated.Audiences is set but no delegation authorizer is wired — set embedded.Deps.DelegatedAuthorization")
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
