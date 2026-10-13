package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/open-rails/authkit/provider"
)

// Probe checks one optional dependency or degraded feature.
type Probe struct {
	// Name is stable for dashboards: authkit_config, authkit_email,
	// authkit_sms, authkit_redis, authkit_two_factor, authkit_issuer_keys and
	// authkit_provider_<name>.
	Name string
	// Check returns nil while the dependency is usable; it honors ctx.
	Check func(context.Context) error
}

// degrade records a survivable problem New handled by switching off or
// defaulting the feature it concerns.
func (s *Engine) degrade(problem error) {
	slog.Warn(problem.Error())
	s.degraded = append(s.degraded, problem)
}

// Ready reports whether the engine can serve: PostgreSQL answers, River runs
// (its own since Start, or the host's fleet bound to RiverJobs), and a signing
// engine holds an active key. Optional dependencies never fail it (Probes).
func (s *Engine) Ready(ctx context.Context) error {
	if s.pg != nil {
		if err := s.pg.Ping(ctx); err != nil {
			return fmt.Errorf("authkit: postgres: %w", err)
		}
	}
	if err := s.riverReady(); err != nil {
		return err
	}
	if !s.cfg.Keys.VerifyOnly && s.keys.ActiveSigner() == nil {
		return errors.New("authkit: signing keys: the key source has no active signing key")
	}
	return nil
}

func (s *Engine) riverReady() error {
	m := s.maintenance
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case m.closed:
		return errors.New("authkit: river: the client is closed")
	case m.failed:
		return errors.New("authkit: river: composing RiverJobs failed; recreate the client")
	case !m.started || m.client == nil:
		return errors.New("authkit: river: not running; call Start")
	}
	if m.own {
		select {
		case <-m.client.Stopped():
			return errors.New("authkit: river: AuthKit's River client stopped")
		default:
		}
	}
	return nil
}

// Probes lists the optional dependencies and degraded features, for the
// host's dependency supervisor; none of them fails Ready.
func (s *Engine) Probes() []Probe {
	out := []Probe{{Name: "authkit_config", Check: func(context.Context) error { return errors.Join(s.degraded...) }}}
	if s.email != nil {
		out = append(out, Probe{Name: "authkit_email", Check: func(context.Context) error { _, err := s.EmailHealth(); return err }})
	}
	if s.sms != nil {
		out = append(out, Probe{Name: "authkit_sms", Check: func(context.Context) error { _, err := s.SMSHealth(); return err }})
	}
	if s.redis != nil {
		out = append(out, Probe{Name: "authkit_redis", Check: func(ctx context.Context) error {
			ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			if err := s.redis.Ping(ctx).Err(); err != nil {
				return fmt.Errorf("authkit: Redis unreachable, so rate limits and spent DPoP proofs are per process until it answers: %w", err)
			}
			return nil
		}})
	}
	if s.TwoFactorEnabled() && s.signs {
		out = append(out, Probe{Name: "authkit_two_factor", Check: func(context.Context) error { return s.secondFactorProblem() }})
	}
	out = append(out, Probe{Name: "authkit_issuer_keys", Check: s.checkIssuerKeys})
	listed := map[string]bool{}
	for _, p := range s.configuredProviders {
		name := p.Name()
		if listed[name] {
			continue
		}
		listed[name] = true
		check := func(context.Context) error { return s.providerProblems[name] }
		if hc, ok := p.(provider.HealthChecker); ok && s.providerProblems[name] == nil {
			check = hc.CheckHealth
		}
		out = append(out, Probe{Name: "authkit_provider_" + name, Check: check})
	}
	return out
}

// checkIssuerKeys fails naming every remote issuer whose JWKS last failed to
// load: remote applications' (Config.Resource) and private_key_jwt clients'.
// Only those issuers' tokens are refused meanwhile.
func (s *Engine) checkIssuerKeys(ctx context.Context) error {
	var errs []error
	if s.resource != nil {
		errs = append(errs, s.resource.v.CheckIssuerKeys(ctx), s.resource.assertions.CheckIssuerKeys(ctx))
	}
	errs = append(errs, s.clientAssertionVerifier().v.CheckIssuerKeys(ctx))
	return errors.Join(errs...)
}

// applyProviders keeps the usable identity providers. A misconfigured one is
// disabled alone, its problem reported by its probe: one that fails Validate,
// shares its name or issuer with another (both are disabled), claims one of
// this deployment's account issuers, or posts its response cross-site
// (form_post) to a deployment that is not HTTPS.
func (s *Engine) applyProviders(providers []provider.Provider) {
	s.providerProblems = map[string]error{}
	names, issuers := map[string]int{}, map[string]int{}
	for i, p := range providers {
		if p == nil {
			s.degrade(fmt.Errorf("authkit: Deps.Providers[%d] is nil; it is ignored", i))
			continue
		}
		s.configuredProviders = append(s.configuredProviders, p)
		names[p.Name()]++
		issuers[issuerKey(p.Issuer())]++
	}
	httpsDeployment := strings.HasPrefix(strings.ToLower(strings.TrimSpace(s.cfg.Frontend.BaseURL)), "https://")
	for _, p := range s.configuredProviders {
		name := p.Name()
		problem := p.Validate()
		switch {
		case problem != nil:
		case names[name] > 1:
			problem = fmt.Errorf("%w: provider %q listed twice", provider.ErrInvalid, name)
		case s.accountIssuer(p.Issuer()):
			problem = fmt.Errorf("%w: provider %q uses reserved issuer %q", provider.ErrInvalid, name, p.Issuer())
		case issuers[issuerKey(p.Issuer())] > 1:
			problem = fmt.Errorf("%w: provider %q shares issuer %q with another provider", provider.ErrInvalid, name, p.Issuer())
		case s.cfg.HTTP != nil && p.ResponseModeFormPost() && !httpsDeployment:
			problem = fmt.Errorf("%w: provider %q uses response_mode=form_post, which needs an HTTPS deployment (SameSite=None; Secure state cookie); set Frontend.BaseURL to an https URL", provider.ErrInvalid, name)
		}
		if problem != nil {
			if s.providerProblems[name] == nil {
				s.providerProblems[name] = fmt.Errorf("authkit: identity provider %q is disabled: %w", name, problem)
				s.degrade(s.providerProblems[name])
			}
			continue
		}
		s.providers = append(s.providers, p)
	}
}

// accountIssuer reports whether issuer is one of this deployment's account
// issuers, which no identity provider may claim.
func (s *Engine) accountIssuer(issuer string) bool {
	key := issuerKey(issuer)
	for _, own := range s.cfg.Token.AccountIssuers {
		if issuerKey(own) == key {
			return true
		}
	}
	return false
}

// Providers are the usable identity providers (applyProviders).
func (s *Engine) Providers() []provider.Provider { return s.providers }
