package authcore

import (
	"context"
	"errors"
	"testing"

	"github.com/open-rails/authkit/internal/passkeytest"
	memorystore "github.com/open-rails/authkit/internal/storage/memory"
	"github.com/open-rails/authkit/internal/testdb"
)

// A validly signed assertion without user verification is refused on every
// assertion path, even though the credential itself was registered with UV.
func TestPasskeyLoginRejectsValidNonUVAssertion(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	cfg := Config{
		Keys: staticTestKeys(t),
		Token: TokenConfig{
			Issuer:            "https://example.org",
			IssuedAudiences:   []string{"test-app"},
			ExpectedAudiences: []string{"test-app"},
		},
		Passkeys: PasskeyConfig{
			RPID:          "example.org",
			RPDisplayName: "Example",
			Origins:       []string{"https://example.org"},
		},
		Ephemeral: EphemeralConfig{AllowMemory: true},
	}
	svc, err := newFromConfig(cfg, pool, WithEphemeralStore(memorystore.NewKV()))
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	user, err := svc.CreateUser(ctx, "passkey-vector@test.example", "passkeyvector")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })

	authn := passkeytest.New(t, "https://example.org")
	creation, err := svc.BeginPasskeyRegistration(ctx, user.ID)
	if err != nil {
		t.Fatalf("begin registration: %v", err)
	}
	if _, err := svc.FinishPasskeyRegistration(ctx, user.ID, authn.Register(t, creation)); err != nil {
		t.Fatalf("finish registration: %v", err)
	}

	authn.UserVerified = false
	assertion, err := svc.BeginPasskeyLogin(ctx, "")
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	_, err = svc.FinishPasskeyLogin(ctx, authn.Assert(t, assertion, 1), "test", nil)
	if !errors.Is(err, ErrPasskeyUserVerificationRequired) {
		t.Fatalf("FinishPasskeyLogin err = %v, want ErrPasskeyUserVerificationRequired", err)
	}

	assertion, err = svc.BeginDiscoverablePasskeyVerification(ctx)
	if err != nil {
		t.Fatalf("begin verification: %v", err)
	}
	if _, err := svc.FinishDiscoverablePasskeyVerification(ctx, authn.Assert(t, assertion, 2)); err == nil {
		t.Fatal("FinishDiscoverablePasskeyVerification accepted an assertion without user verification")
	}
}
