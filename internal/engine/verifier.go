package engine

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

// newVerifier builds the engine's request verifier: its own issuer's keys,
// the engine as enricher and permission checker.
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
	v.WithService(s).WithPermissionChecker(s, cfg.Token.Issuer)
	return v, nil
}

// NewVerifier builds an extra verifier for the host's own resource routes. It
// trusts no issuer until the host adds one (AddIssuer, LoadRemoteApplications)
// and shares this engine's API-key resolver, stored remote applications,
// permission checks and DPoP replay store. DPoP proofs are
// checked against the issuer's origin plus the request path unless an option
// (verify.WithDPoPRequestURL) says otherwise.
func (s *Engine) NewVerifier(opts ...verify.VerifierOption) *verify.Verifier {
	cfg := s.cfg
	base := []verify.VerifierOption{
		verify.WithAPIKeyPrefix(cfg.APIKeys.Prefix),
		verify.WithDPoP(s.ClaimDPoPProof, s.issuerRequestURL),
	}
	if !cfg.Applications.AllowPrivateNetworkJWKS {
		base = append(base, verify.WithSSRFGuard())
	}
	v := verify.NewVerifier(append(base, opts...)...)
	v.WithService(s).WithPermissionChecker(s, cfg.Token.Issuer)
	return v
}

// issuerRequestURL is r's URL on the issuer's origin; "" (no DPoP proof can
// match) when the issuer is not a URL.
func (s *Engine) issuerRequestURL(r *http.Request) string {
	issuer, err := url.Parse(strings.TrimSpace(s.cfg.Token.Issuer))
	if err != nil || issuer.Scheme == "" || issuer.Host == "" || issuer.User != nil {
		return ""
	}
	return issuer.Scheme + "://" + issuer.Host + r.URL.EscapedPath()
}
