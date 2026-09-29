// Package testhttp constructs isolated local runtimes for HTTP adapter tests.
package testhttp

import (
	"crypto"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
)

func Runtime(t testing.TB) *authkit.Runtime {
	t.Helper()
	pg := testdb.ScratchPostgres(t)
	signer, err := jwtkit.NewRSASigner(2048, "runtime-http-test")
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := authkit.New(authkit.Config{
		Token:        authkit.TokenConfig{Issuer: "https://identity.example", IssuedAudiences: []string{"test"}},
		Keys:         authkit.KeysConfig{Source: jwtkit.StaticKeySource{Active: signer, Pubs: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}}},
		TwoFactor:    authkit.TwoFactorConfig{Mode: iam.TwoFactorDisabled},
		Registration: authkit.RegistrationConfig{NativeUserMode: iam.RegistrationModeOpen, Verification: iam.RegistrationVerificationNone},
	}, authkit.Deps{Postgres: pg.Pool, River: authkit.RiverFromHost()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	return runtime
}
