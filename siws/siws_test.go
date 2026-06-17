package siws

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestConstructMessage(t *testing.T) {
	statement := "Sign in to test app"
	uri := "https://example.com"
	version := "1"
	chainID := "mainnet"
	expTime := "2025-12-05T12:00:00Z"

	input := SignInInput{
		Domain:         "example.com",
		Address:        "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
		Statement:      &statement,
		URI:            &uri,
		Version:        &version,
		ChainID:        &chainID,
		Nonce:          "abc12345",
		IssuedAt:       "2025-12-05T11:00:00Z",
		ExpirationTime: &expTime,
	}

	msg := ConstructMessage(input)

	// Check required parts
	if !contains(msg, "example.com wants you to sign in with your Solana account:") {
		t.Error("missing header")
	}
	if !contains(msg, "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU") {
		t.Error("missing address")
	}
	if !contains(msg, "Sign in to test app") {
		t.Error("missing statement")
	}
	if !contains(msg, "Nonce: abc12345") {
		t.Error("missing nonce")
	}
	if !contains(msg, "Issued At: 2025-12-05T11:00:00Z") {
		t.Error("missing issued at")
	}
}

func TestConstructMessageMinimal(t *testing.T) {
	input := SignInInput{
		Domain:   "example.com",
		Address:  "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
		Nonce:    "abc12345",
		IssuedAt: "2025-12-05T11:00:00Z",
	}

	msg := ConstructMessage(input)

	expected := `example.com wants you to sign in with your Solana account:
7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU

Nonce: abc12345
Issued At: 2025-12-05T11:00:00Z`

	if msg != expected {
		t.Errorf("minimal message mismatch:\ngot:\n%s\n\nwant:\n%s", msg, expected)
	}
}

func TestParseMessage(t *testing.T) {
	statement := "Sign in to test app"
	uri := "https://example.com"
	version := "1"
	chainID := "mainnet"
	expTime := "2025-12-05T12:00:00Z"

	original := SignInInput{
		Domain:         "example.com",
		Address:        "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
		Statement:      &statement,
		URI:            &uri,
		Version:        &version,
		ChainID:        &chainID,
		Nonce:          "abc12345",
		IssuedAt:       "2025-12-05T11:00:00Z",
		ExpirationTime: &expTime,
	}

	msg := ConstructMessage(original)
	parsed, err := ParseMessage(msg)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if parsed.Domain != original.Domain {
		t.Errorf("domain mismatch: got %s, want %s", parsed.Domain, original.Domain)
	}
	if parsed.Address != original.Address {
		t.Errorf("address mismatch: got %s, want %s", parsed.Address, original.Address)
	}
	if parsed.Nonce != original.Nonce {
		t.Errorf("nonce mismatch: got %s, want %s", parsed.Nonce, original.Nonce)
	}
	if parsed.IssuedAt != original.IssuedAt {
		t.Errorf("issuedAt mismatch: got %s, want %s", parsed.IssuedAt, original.IssuedAt)
	}
}

func TestGenerateNonce(t *testing.T) {
	nonce1, err := GenerateNonce()
	if err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}
	if len(nonce1) < 8 {
		t.Errorf("nonce too short: %d chars", len(nonce1))
	}

	nonce2, err := GenerateNonce()
	if err != nil {
		t.Fatalf("failed to generate second nonce: %v", err)
	}

	if nonce1 == nonce2 {
		t.Error("nonces should be unique")
	}

	// SIWS / EIP-4361 ABNF requires nonce = 8*( ALPHA / DIGIT ): purely
	// alphanumeric. base64url chars '-' and '_' must never appear.
	for _, n := range []string{nonce1, nonce2} {
		for _, c := range n {
			isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
			if !isAlphaNum {
				t.Errorf("nonce contains non-alphanumeric character %q: %s", c, n)
			}
		}
	}
}

func TestNewSignInInput(t *testing.T) {
	input, err := NewSignInInput("example.com", "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
		WithStatement("Test sign in"),
		WithChainID("devnet"),
	)
	if err != nil {
		t.Fatalf("failed to create input: %v", err)
	}

	if input.Domain != "example.com" {
		t.Errorf("wrong domain: %s", input.Domain)
	}
	if input.Nonce == "" {
		t.Error("nonce should be set")
	}
	if input.IssuedAt == "" {
		t.Error("issuedAt should be set")
	}
	if input.Statement == nil || *input.Statement != "Test sign in" {
		t.Error("statement not set")
	}
	if input.ChainID == nil || *input.ChainID != "devnet" {
		t.Error("chainID not set")
	}
}

func TestBase58ToPublicKey(t *testing.T) {
	// Generate a real keypair
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Convert to base58 and back
	address := PublicKeyToBase58(pub)
	decoded, err := Base58ToPublicKey(address)
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if !pub.Equal(decoded) {
		t.Error("public key mismatch after round-trip")
	}
}

func TestValidateAddress(t *testing.T) {
	// Valid address
	err := ValidateAddress("7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU")
	if err != nil {
		t.Errorf("valid address rejected: %v", err)
	}

	// Invalid address (too short)
	err = ValidateAddress("abc")
	if err == nil {
		t.Error("invalid address accepted")
	}

	// Invalid base58 characters
	err = ValidateAddress("0OIl") // 0, O, I, l are not valid base58
	if err == nil {
		t.Error("invalid base58 accepted")
	}
}

func TestVerifySignature(t *testing.T) {
	// Generate keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	address := PublicKeyToBase58(pub)

	// Create and sign a message
	input, err := NewSignInInput("example.com", address, WithStatement("Test"))
	if err != nil {
		t.Fatalf("failed to create input: %v", err)
	}

	message := ConstructMessage(input)
	messageBytes := []byte(message)
	signature := ed25519.Sign(priv, messageBytes)

	output := SignInOutput{
		Account: AccountInfo{
			Address:   address,
			PublicKey: pub,
		},
		Signature:     signature,
		SignedMessage: messageBytes,
	}

	// Verify should succeed
	err = VerifySignature(output)
	if err != nil {
		t.Errorf("valid signature rejected: %v", err)
	}

	// Tamper with signature
	output.Signature[0] ^= 0xFF
	err = VerifySignature(output)
	if err == nil {
		t.Error("tampered signature accepted")
	}
}

func TestVerify(t *testing.T) {
	// Generate keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	address := PublicKeyToBase58(pub)

	// Create input
	input, err := NewSignInInput("example.com", address, WithStatement("Test sign in"))
	if err != nil {
		t.Fatalf("failed to create input: %v", err)
	}

	// Simulate wallet signing
	message := ConstructMessage(input)
	messageBytes := []byte(message)
	signature := ed25519.Sign(priv, messageBytes)

	output := SignInOutput{
		Account: AccountInfo{
			Address:   address,
			PublicKey: pub,
		},
		Signature:     signature,
		SignedMessage: messageBytes,
	}

	// Full verify should succeed
	err = Verify(input, output)
	if err != nil {
		t.Errorf("valid verify failed: %v", err)
	}

	// Address mismatch should fail
	badInput := input
	badInput.Address = "DifferentAddress12345678901234567890123456789"
	err = Verify(badInput, output)
	if err == nil {
		t.Error("address mismatch not detected")
	}
}

func TestValidateTimestamps(t *testing.T) {
	now := time.Now().UTC()

	// Valid timestamps
	exp := now.Add(10 * time.Minute).Format(time.RFC3339)
	input := SignInInput{
		IssuedAt:       now.Format(time.RFC3339),
		ExpirationTime: &exp,
	}
	err := ValidateTimestamps(input)
	if err != nil {
		t.Errorf("valid timestamps rejected: %v", err)
	}

	// Expired
	exp = now.Add(-10 * time.Minute).Format(time.RFC3339)
	input.ExpirationTime = &exp
	err = ValidateTimestamps(input)
	if err == nil {
		t.Error("expired message accepted")
	}

	// Not yet valid
	input.ExpirationTime = nil
	nb := now.Add(10 * time.Minute).Format(time.RFC3339)
	input.NotBefore = &nb
	err = ValidateTimestamps(input)
	if err == nil {
		t.Error("not-yet-valid message accepted")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestVerifyRejectsMismatchedPublicKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr := PublicKeyToBase58(pub)
	input := SignInInput{Domain: "example.com", Address: addr, Nonce: "abc12345", IssuedAt: time.Now().UTC().Format(time.RFC3339)}
	msg := ConstructMessage(input)
	sig := ed25519.Sign(priv, []byte(msg))

	// Correct, consistent public key passes.
	good := SignInOutput{
		Account:       AccountInfo{Address: addr, PublicKey: pub},
		Signature:     sig,
		SignedMessage: []byte(msg),
	}
	if err := Verify(input, good); err != nil {
		t.Fatalf("expected valid verify, got %v", err)
	}

	// A bogus PublicKey field that does not match the address must be rejected
	// even though the signature itself is valid for the address.
	bogus := make([]byte, ed25519.PublicKeySize)
	bad := good
	bad.Account.PublicKey = bogus
	if err := Verify(input, bad); err == nil {
		t.Fatal("expected error for mismatched public key, got nil")
	}
}

func TestVerifyRejectsBadSignatureLength(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr := PublicKeyToBase58(pub)
	input := SignInInput{Domain: "example.com", Address: addr, Nonce: "abc12345", IssuedAt: time.Now().UTC().Format(time.RFC3339)}
	msg := ConstructMessage(input)
	sig := ed25519.Sign(priv, []byte(msg))

	out := SignInOutput{
		Account:       AccountInfo{Address: addr},
		Signature:     sig[:len(sig)-1], // truncated
		SignedMessage: []byte(msg),
	}
	if err := Verify(input, out); err == nil {
		t.Fatal("expected error for short signature, got nil")
	}
}
