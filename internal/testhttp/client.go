// Package testhttp is the adapters' preset over authtest.New.
package testhttp

import (
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// Client builds a Client serving httpCfg (zero: headless) with Google and
// GitHub providers, so provider routes exist.
func Client(t testing.TB, httpCfg authkit.HTTPConfig) *authkit.Client {
	t.Helper()
	return ClientAt(t, authtest.Issuer, httpCfg)
}

// ClientAt is Client with its issuer, whose path is the surface's base path.
// GitHub's static endpoints let a login start without network access.
func ClientAt(t testing.TB, issuer string, httpCfg authkit.HTTPConfig) *authkit.Client {
	t.Helper()
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Token = authkit.TokenConfig{Issuer: issuer, IssuedAudiences: []string{"test"}}
		c.TwoFactor.Mode = iam.TwoFactorDisabled
		c.Identity.Providers = []authprovider.Provider{authprovider.Google("google-client", "google-secret"), authprovider.GitHub("github-client", "github-secret")}
		c.HTTP = httpCfg
	}), authtest.WithDeps(func(d *authkit.Deps) { d.River = authkit.RiverFromHost() }))
	return auth
}

// HTTP is a rate-limit-free, direct-peer HTTP configuration for tests.
func HTTP() authkit.HTTPConfig {
	return authkit.HTTPConfig{DirectPeerIP: true, DisableRateLimiting: true}
}
