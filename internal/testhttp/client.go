// Package testhttp constructs isolated AuthKit instances for HTTP adapter tests.
package testhttp

import (
	"context"
	"crypto"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
)

// Client builds a Client serving httpCfg (zero: headless) on a scratch database,
// with Google and GitHub providers so provider routes exist.
func Client(t testing.TB, httpCfg authkit.HTTPConfig) *authkit.Client {
	t.Helper()
	return ClientAt(t, "https://example.com", httpCfg)
}

// ClientAt is Client with its issuer, whose path is the surface's base path.
// GitHub's static endpoints let a login start without network access.
func ClientAt(t testing.TB, issuer string, httpCfg authkit.HTTPConfig) *authkit.Client {
	t.Helper()
	pg := testdb.ScratchPostgres(t)
	signer, err := jwtkit.NewRSASigner(2048, "runtime-http-test")
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := authkit.New(context.Background(), authkit.Config{
		Token:        authkit.TokenConfig{Issuer: issuer, IssuedAudiences: []string{"test"}},
		Keys:         authkit.KeysConfig{Source: jwtkit.StaticKeySource{Active: signer, Pubs: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}}},
		TwoFactor:    authkit.TwoFactorConfig{Mode: iam.TwoFactorDisabled},
		Registration: authkit.RegistrationConfig{NativeUserMode: iam.RegistrationModeOpen, Verification: iam.RegistrationVerificationNone},
		Identity:     authkit.IdentityConfig{Providers: []authprovider.Provider{authprovider.Google("google-client", "google-secret"), authprovider.GitHub("github-client", "github-secret")}},
		HTTP:         httpCfg,
	}, authkit.Deps{Postgres: pg.Pool, River: authkit.RiverFromHost()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	return runtime
}

// HTTP is a rate-limit-free, direct-peer HTTP configuration for tests.
func HTTP() authkit.HTTPConfig {
	return authkit.HTTPConfig{DirectPeerIP: true, DisableRateLimiting: true}
}
