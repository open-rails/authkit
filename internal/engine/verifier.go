package engine

import (
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

// newVerifier builds the engine's request verifier: its own issuer's keys,
// the engine as enricher, liveness source and permission checker.
func (s *Engine) newVerifier() (*verify.Verifier, error) {
	cfg := s.cfg
	opts := []verify.VerifierOption{
		verify.WithSkew(5 * time.Second),
		verify.WithAPIKeyPrefix(cfg.APIKeys.Prefix),
		verify.WithRemoteApplicationAudiences(cfg.Token.ExpectedAudiences...),
		// #240: required 2FA challenges every un-enrolled user on their next
		// request, not just at mint time.
		verify.WithRequireMFAEnrollment(cfg.TwoFactor.Mode == iam.TwoFactorRequired),
	}
	// Applications.AllowPrivateNetworkJWKS is the local-federation carve-out
	// (#257) from the SSRF guard on JWKS fetches.
	if !cfg.Applications.AllowPrivateNetworkJWKS {
		opts = append(opts, verify.WithSSRFGuard())
	}
	v := verify.NewVerifier(opts...)
	if cfg.Token.Issuer != "" {
		if err := v.AddIssuer(cfg.Token.Issuer, cfg.Token.ExpectedAudiences, verify.IssuerOptions{
			PublicKeys: s.PublicKeysByKID,
			IsLocal:    true,
		}); err != nil {
			return nil, err
		}
	}
	v.WithService(s).WithLiveness(s).WithPermissionChecker(s, cfg.Token.Issuer)
	return v, nil
}
