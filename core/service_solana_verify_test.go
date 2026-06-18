package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/open-rails/authkit/siws"
)

// signedChallenge builds a valid, freshly-signed SIWS challenge/output pair for
// the given domain, returning the stored challenge data, the parsed input, and
// the signed output. expiresAt sets the server-issued window.
func signedChallenge(t *testing.T, domain string, expiresAt time.Time) (siws.ChallengeData, siws.SignInInput, siws.SignInOutput) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	address := siws.PublicKeyToBase58(pub)

	input, err := siws.NewSignInInput(domain, address, siws.WithChainID("mainnet"))
	if err != nil {
		t.Fatalf("new input: %v", err)
	}

	message := siws.ConstructMessage(input)
	output := siws.SignInOutput{
		Account: siws.AccountInfo{
			Address:   address,
			PublicKey: pub,
		},
		Signature:     ed25519.Sign(priv, []byte(message)),
		SignedMessage: []byte(message),
	}

	parsed, err := siws.ParseMessage(message)
	if err != nil {
		t.Fatalf("parse message: %v", err)
	}

	cd := siws.ChallengeData{
		Address:   address,
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: expiresAt,
		Input:     input,
	}
	return cd, parsed, output
}

func TestVerifySIWSChallenge_Valid(t *testing.T) {
	now := time.Now().UTC()
	cd, parsed, output := signedChallenge(t, "example.com", now.Add(15*time.Minute))

	if err := verifySIWSChallenge(cd, parsed, output, now); err != nil {
		t.Fatalf("expected valid challenge, got error: %v", err)
	}
}

// Finding 3: a challenge past its server-issued ExpiresAt must be rejected even
// when the client-signed message carries a later (or absent) expirationTime.
func TestVerifySIWSChallenge_ServerExpiryEnforced(t *testing.T) {
	now := time.Now().UTC()
	// Server window already closed (issued 20m ago, 15m TTL)...
	cd, parsed, output := signedChallenge(t, "example.com", now.Add(-5*time.Minute))

	// ...but the client-signed message claims a far-future expirationTime.
	future := now.Add(24 * time.Hour).Format(time.RFC3339)
	parsed.ExpirationTime = &future

	err := verifySIWSChallenge(cd, parsed, output, now)
	if err == nil {
		t.Fatal("expected rejection for server-side expired challenge, got nil")
	}
	if got := err.Error(); got != "challenge expired" {
		t.Fatalf("expected \"challenge expired\", got %q", got)
	}
}

func TestVerifySIWSChallenge_DomainMismatch(t *testing.T) {
	now := time.Now().UTC()
	cd, parsed, output := signedChallenge(t, "example.com", now.Add(15*time.Minute))

	// Challenge was issued for a different domain than the signed message.
	cd.Input.Domain = "evil.com"

	if err := verifySIWSChallenge(cd, parsed, output, now); err == nil {
		t.Fatal("expected domain mismatch rejection, got nil")
	}
}

func TestVerifySIWSChallenge_ChainIDMismatch(t *testing.T) {
	now := time.Now().UTC()
	cd, parsed, output := signedChallenge(t, "example.com", now.Add(15*time.Minute))

	// Server issued the challenge for a different network than the wallet signed.
	devnet := "devnet"
	cd.Input.ChainID = &devnet

	if err := verifySIWSChallenge(cd, parsed, output, now); err == nil {
		t.Fatal("expected chain id mismatch rejection, got nil")
	}
}

func TestVerifySIWSChallenge_URIMismatch(t *testing.T) {
	now := time.Now().UTC()
	cd, parsed, output := signedChallenge(t, "example.com", now.Add(15*time.Minute))

	// Server bound a URI the wallet's signed message does not carry.
	uri := "https://example.com/login"
	cd.Input.URI = &uri

	if err := verifySIWSChallenge(cd, parsed, output, now); err == nil {
		t.Fatal("expected uri mismatch rejection, got nil")
	}
}

func TestVerifySIWSChallenge_AddressMismatch(t *testing.T) {
	now := time.Now().UTC()
	cd, parsed, output := signedChallenge(t, "example.com", now.Add(15*time.Minute))

	cd.Address = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"

	if err := verifySIWSChallenge(cd, parsed, output, now); err == nil {
		t.Fatal("expected address mismatch rejection, got nil")
	}
}

func TestVerifySIWSChallenge_PublicKeyMismatch(t *testing.T) {
	now := time.Now().UTC()
	cd, parsed, output := signedChallenge(t, "example.com", now.Add(15*time.Minute))

	// Supply a public key inconsistent with the address.
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	output.Account.PublicKey = otherPub

	if err := verifySIWSChallenge(cd, parsed, output, now); err == nil {
		t.Fatal("expected public key mismatch rejection, got nil")
	}
}

func TestVerifySIWSChallenge_BadSignature(t *testing.T) {
	now := time.Now().UTC()
	cd, parsed, output := signedChallenge(t, "example.com", now.Add(15*time.Minute))

	// Corrupt the signature.
	output.Signature[0] ^= 0xFF

	if err := verifySIWSChallenge(cd, parsed, output, now); err == nil {
		t.Fatal("expected signature verification failure, got nil")
	}
}
