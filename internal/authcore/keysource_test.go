package authcore

import (
	"crypto"
	"testing"

	"github.com/open-rails/authkit/jwtkit"
)

// testKeySource returns an in-memory signing KeySource for tests. (#208: the
// generated-dev-keys machinery is unexported — it is reachable only through
// jwtkit.ResolveKeySource's explicit AllowEphemeralDevKeys opt-in — so tests
// build a static source from a fresh RSA signer instead of writing .runtime files.)
func testKeySource(t *testing.T) jwtkit.StaticKeySource {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "test-kid")
	if err != nil {
		t.Fatalf("test signer: %v", err)
	}
	return jwtkit.StaticKeySource{
		Active: signer,
		Pubs:   map[string]crypto.PublicKey{"test-kid": signer.PublicKey()},
	}
}
