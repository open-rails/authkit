package embedded

import (
	"context"
	"strings"
	"testing"

	memorystore "github.com/open-rails/authkit/internal/storage/memory"
)

// ak#314: every formerly Environment-gated behaviour is an explicit field that
// is OFF by default and on only when set. Sibling pins: AllowPrivateNetworkJWKS
// (ssrf_validation_test.go), AllowEphemeralDevKeys (constructor_keys_test.go),
// Ephemeral.AllowMemory (embedded/ephemeral_backend_test.go), the authhttp
// client-IP posture (authhttp/config_test.go).
func TestAllowMissingSendersIsOffByDefault(t *testing.T) {
	ctx := context.Background()
	verified := Config{Registration: RegistrationConfig{Verification: RegistrationVerificationRequired}}

	strict := mustNewWithKeys(t, verified, Keyset{}, WithEphemeralStore(memorystore.NewKV()))
	_, err := strict.CreatePendingRegistrationWithLanguage(ctx, "strict@example.com", "strictuser", "argon2id$hash", 0, "")
	if err == nil || !strings.Contains(err.Error(), "email sender not configured") {
		t.Fatalf("no sender and no opt-in must refuse, got %v", err)
	}

	verified.Registration.AllowMissingSenders = true
	lenient := mustNewWithKeys(t, verified, Keyset{}, WithEphemeralStore(memorystore.NewKV()))
	code, err := lenient.CreatePendingRegistrationWithLanguage(ctx, "lenient@example.com", "lenientuser", "argon2id$hash", 0, "")
	if err != nil || len(code) != 6 {
		t.Fatalf("AllowMissingSenders must let registration proceed undelivered: code=%q err=%v", code, err)
	}
}

func TestSolanaNetworkDefaultsToMainnet(t *testing.T) {
	if got := solanaChainIDForConfig(Config{}); got != "mainnet" {
		t.Fatalf("empty SolanaNetwork = %q, want mainnet", got)
	}
	if got := solanaChainIDForConfig(Config{SolanaNetwork: "devnet"}); got != "devnet" {
		t.Fatalf("explicit SolanaNetwork = %q, want devnet", got)
	}
}
