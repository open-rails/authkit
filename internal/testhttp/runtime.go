// Package testhttp constructs isolated local runtimes for HTTP adapter tests.
package testhttp

import (
	"crypto"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
)

// Runtime builds a runtime serving httpCfg (nil: headless) on a scratch
// database, with one Google provider so provider routes exist.
func Runtime(t testing.TB, httpCfg *authkit.HTTPConfig) *authkit.Runtime {
	t.Helper()
	pg := testdb.ScratchPostgres(t)
	signer, err := jwtkit.NewRSASigner(2048, "runtime-http-test")
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := authkit.New(authkit.Config{
		Token:        authkit.TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"test"}},
		Keys:         authkit.KeysConfig{Source: jwtkit.StaticKeySource{Active: signer, Pubs: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}}},
		TwoFactor:    authkit.TwoFactorConfig{Mode: iam.TwoFactorDisabled},
		Registration: authkit.RegistrationConfig{NativeUserMode: iam.RegistrationModeOpen, Verification: iam.RegistrationVerificationNone},
		Identity:     authkit.IdentityConfig{Providers: []authprovider.Provider{authprovider.Google("google-client", "google-secret")}},
		HTTP:         httpCfg,
	}, authkit.Deps{Postgres: pg.Pool, River: authkit.RiverFromHost()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	return runtime
}

// HTTP is a rate-limit-free, direct-peer HTTP configuration for tests.
func HTTP() *authkit.HTTPConfig {
	return &authkit.HTTPConfig{DirectPeerIP: true, DisableRateLimiting: true}
}
