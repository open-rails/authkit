package authcore

import (
	"context"
	"testing"

	memorystore "github.com/open-rails/authkit/storage/memory"
)

// TestBeginPasskeyLogin_NoEnumerationOracle is the AK2-PK-002 regression: passkey
// login-begin must return an identical, discoverable assertion (empty
// allowCredentials) regardless of whether the supplied identifier matches a user.
// Branching to a credential-scoped assertion for known users would leak both
// account existence and the user's credential IDs to an unauthenticated caller.
// No DB needed — the assertion is built from config + the ephemeral session store.
func TestBeginPasskeyLogin_NoEnumerationOracle(t *testing.T) {
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://example.org"}, Passkeys: PasskeyConfig{RPID: "example.org", Origins: []string{"https://example.org"}}}, Keyset{}, WithEphemeralStore(memorystore.NewKV()))
	ctx := context.Background()

	for _, identifier := range []string{"", "nobody@example.org", "ghost", "+15555550100"} {
		a, err := svc.BeginPasskeyLogin(ctx, identifier)
		if err != nil {
			t.Fatalf("identifier %q: BeginPasskeyLogin: %v", identifier, err)
		}
		if a == nil {
			t.Fatalf("identifier %q: nil assertion", identifier)
		}
		// Discoverable assertion ⇒ empty allowCredentials for every input, so the
		// response cannot be used to probe existence or harvest credential IDs.
		if n := len(a.Response.AllowedCredentials); n != 0 {
			t.Errorf("identifier %q: allowCredentials must be empty (discoverable), got %d — enumeration oracle", identifier, n)
		}
	}
}
