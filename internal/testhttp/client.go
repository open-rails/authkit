// Package testhttp is the adapters' preset over authtest.New.
package testhttp

import (
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/provider"
)

// Client builds a Client serving httpCfg (nil: headless) with Google and
// GitHub providers, so provider routes exist; opts adjust the rest. Unless
// httpCfg sets RateLimits, authtest's lifted limits apply.
func Client(t testing.TB, httpCfg *authkit.HTTPConfig, opts ...authtest.Option) *authkit.Client {
	t.Helper()
	return ClientAt(t, authtest.Issuer, httpCfg, opts...)
}

// ClientAt is Client with its issuer, whose path is the surface's base path.
// GitHub's static endpoints let a login start without network access.
func ClientAt(t testing.TB, issuer string, httpCfg *authkit.HTTPConfig, opts ...authtest.Option) *authkit.Client {
	t.Helper()
	auth, _ := authtest.New(t, append([]authtest.Option{authtest.WithConfig(func(c *authkit.Config) {
		c.Token = authkit.TokenConfig{Issuer: issuer, IssuedAudiences: []string{"test"}}
		c.TwoFactor.Mode = iam.TwoFactorDisabled
		c.River.HostOwned = true
		if httpCfg != nil && httpCfg.RateLimits == nil {
			h := *httpCfg
			h.RateLimits = c.HTTP.RateLimits
			httpCfg = &h
		}
		c.HTTP = httpCfg
	}), authtest.WithDeps(func(d *authkit.Deps) {
		d.Providers = []provider.Provider{provider.Google("google-client", "google-secret"), provider.GitHub("github-client", "github-secret")}
	})}, opts...)...)
	return auth
}

// HTTP is a direct-peer HTTP configuration for tests.
func HTTP() *authkit.HTTPConfig { return &authkit.HTTPConfig{DirectPeerIP: true} }
