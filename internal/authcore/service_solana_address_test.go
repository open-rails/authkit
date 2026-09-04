package authcore

import (
	"errors"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/siws"
)

// #323: the address line the wallet rendered and signed must be the account it
// claims, not only the address the challenge was issued for. The signature is
// genuine over the mutated message, so only the address binding can reject it.
func TestVerifySIWSChallenge_MessageAddressMismatch(t *testing.T) {
	now := time.Now().UTC()
	cd, parsed, output := signedChallengeOpts(t, "example.com", now.Add(15*time.Minute), nil, func(in *siws.SignInInput) {
		in.Address = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
	})

	if err := verifySIWSChallenge(cd, parsed, output, now); !errors.Is(err, ErrSIWSAddressMismatch) {
		t.Fatalf("expected ErrSIWSAddressMismatch, got %v", err)
	}
}
