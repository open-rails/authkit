// Package testhttp constructs isolated local runtimes for HTTP adapter tests.
package testhttp

import (
	"crypto"
	"testing"

	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
)

func Runtime(t testing.TB) *embedded.Runtime {
	t.Helper()
	pg := testdb.ScratchPostgres(t)
	signer, err := jwtkit.NewRSASigner(2048, "runtime-http-test")
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := embedded.New(embedded.Config{
		Token:        embedded.TokenConfig{Issuer: "https://identity.example", IssuedAudiences: []string{"test"}},
		Keys:         embedded.KeysConfig{Source: jwtkit.StaticKeySource{Active: signer, Pubs: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}}},
		TwoFactor:    embedded.TwoFactorConfig{Mode: embedded.TwoFactorDisabled},
		Registration: embedded.RegistrationConfig{NativeUserMode: embedded.RegistrationModeOpen, Verification: embedded.RegistrationVerificationNone},
	}, embedded.Deps{Postgres: pg.Pool, River: embedded.RiverFromHost()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	return runtime
}
