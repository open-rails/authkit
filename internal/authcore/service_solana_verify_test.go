package authcore

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/siws"
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

// signedChallengeOpts is signedChallenge with control over BOTH sides: serverOpts
// shape the challenge the server issues and stores, and walletMutate rewrites the
// input the wallet actually renders and signs. The signature is always genuine
// over whatever the wallet rendered, so a rejection can only come from a binding
// check and never from a broken signature.
func signedChallengeOpts(t *testing.T, domain string, expiresAt time.Time, serverOpts []siws.InputOption, walletMutate func(*siws.SignInInput)) (siws.ChallengeData, siws.SignInInput, siws.SignInOutput) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	address := siws.PublicKeyToBase58(pub)

	issued, err := siws.NewSignInInput(domain, address, serverOpts...)
	if err != nil {
		t.Fatalf("new input: %v", err)
	}

	signedInput := issued
	if walletMutate != nil {
		walletMutate(&signedInput)
	}
	message := siws.ConstructMessage(signedInput)
	output := siws.SignInOutput{
		Account:       siws.AccountInfo{Address: address, PublicKey: pub},
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
		Input:     issued,
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
	if !errors.Is(err, ErrSIWSChallengeExpired) {
		t.Fatalf("expected ErrSIWSChallengeExpired, got %v", err)
	}
}

func TestVerifySIWSChallenge_DomainMismatch(t *testing.T) {
	now := time.Now().UTC()
	cd, parsed, output := signedChallenge(t, "example.com", now.Add(15*time.Minute))

	// Challenge was issued for a different domain than the signed message.
	cd.Input.Domain = "evil.com"

	if err := verifySIWSChallenge(cd, parsed, output, now); !errors.Is(err, ErrSIWSDomainInvalid) {
		t.Fatalf("expected ErrSIWSDomainInvalid, got %v", err)
	}
}

func TestVerifySIWSChallenge_AddressMismatch(t *testing.T) {
	now := time.Now().UTC()
	cd, parsed, output := signedChallenge(t, "example.com", now.Add(15*time.Minute))

	cd.Address = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"

	if err := verifySIWSChallenge(cd, parsed, output, now); !errors.Is(err, ErrSIWSAddressMismatch) {
		t.Fatalf("expected ErrSIWSAddressMismatch, got %v", err)
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

	if err := verifySIWSChallenge(cd, parsed, output, now); !errors.Is(err, ErrSIWSSignatureInvalid) {
		t.Fatalf("expected ErrSIWSSignatureInvalid, got %v", err)
	}
}

// #51 left chainId and URI unbound: a message signed for another network, or
// naming another URI, still authenticated against the server's challenge. Both
// are now bound (ak#275, ae/siws-uri-chainid-binding). The signature in each
// case is genuine over what the wallet rendered — only the binding rejects.
func TestVerifySIWSChallenge_ChainIDMismatch(t *testing.T) {
	now := time.Now().UTC()
	cd, parsed, output := signedChallengeOpts(t, "example.com", now.Add(15*time.Minute),
		[]siws.InputOption{siws.WithChainID("mainnet")},
		func(in *siws.SignInInput) { devnet := "devnet"; in.ChainID = &devnet })

	if err := verifySIWSChallenge(cd, parsed, output, now); !errors.Is(err, ErrSIWSChallengeMismatch) {
		t.Fatalf("expected ErrSIWSChallengeMismatch for a devnet signature on a mainnet challenge, got %v", err)
	}
}

func TestVerifySIWSChallenge_URIMismatch(t *testing.T) {
	now := time.Now().UTC()
	cd, parsed, output := signedChallengeOpts(t, "example.com", now.Add(15*time.Minute),
		[]siws.InputOption{siws.WithChainID("mainnet"), siws.WithURI("https://example.com")},
		func(in *siws.SignInInput) { other := "https://example.com/elsewhere"; in.URI = &other })

	if err := verifySIWSChallenge(cd, parsed, output, now); !errors.Is(err, ErrSIWSChallengeMismatch) {
		t.Fatalf("expected ErrSIWSChallengeMismatch for a rewritten URI, got %v", err)
	}
}

// The binding must not cost interop: a wallet that signs the server's message
// verbatim still verifies with BOTH fields populated, and a field the server
// never issued stays unbound (the wallet may add its own URI).
func TestVerifySIWSChallenge_ChainIDAndURIRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	cd, parsed, output := signedChallengeOpts(t, "example.com", now.Add(15*time.Minute),
		[]siws.InputOption{siws.WithChainID("devnet"), siws.WithURI("https://example.com")}, nil)
	if err := verifySIWSChallenge(cd, parsed, output, now); err != nil {
		t.Fatalf("a verbatim signature over a chainId+URI challenge must verify, got %v", err)
	}

	cd, parsed, output = signedChallengeOpts(t, "example.com", now.Add(15*time.Minute),
		[]siws.InputOption{siws.WithChainID("mainnet")},
		func(in *siws.SignInInput) { extra := "https://wallet.example/whatever"; in.URI = &extra })
	if err := verifySIWSChallenge(cd, parsed, output, now); err != nil {
		t.Fatalf("a URI the server never issued must stay unbound, got %v", err)
	}
}
