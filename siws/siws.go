// Package siws implements Sign In With Solana (SIWS) authentication.
// SIWS is part of the Solana Wallet Standard, allowing users to authenticate
// by signing a standardized message with their wallet's Ed25519 private key.
package siws

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/mr-tron/base58"
)

// SignInInput contains the parameters for a SIWS challenge.
// This is sent to the wallet to construct the sign-in message.
type SignInInput struct {
	Domain         string   `json:"domain"`
	Address        string   `json:"address"`
	Statement      *string  `json:"statement,omitempty"`
	URI            *string  `json:"uri,omitempty"`
	Version        *string  `json:"version,omitempty"`
	ChainID        *string  `json:"chainId,omitempty"`
	Nonce          string   `json:"nonce"`
	IssuedAt       string   `json:"issuedAt"`
	ExpirationTime *string  `json:"expirationTime,omitempty"`
	NotBefore      *string  `json:"notBefore,omitempty"`
	RequestID      *string  `json:"requestId,omitempty"`
	Resources      []string `json:"resources,omitempty"`
}

// SignInOutput contains the wallet's response after signing.
type SignInOutput struct {
	Account       AccountInfo `json:"account"`
	Signature     []byte      `json:"signature"`     // 64-byte Ed25519 signature
	SignedMessage []byte      `json:"signedMessage"` // The message bytes that were signed
}

// AccountInfo contains the wallet account details.
type AccountInfo struct {
	Address   string `json:"address"`   // Base58-encoded public key
	PublicKey []byte `json:"publicKey"` // 32-byte Ed25519 public key
}

// ChallengeData is stored server-side while awaiting signature verification.
type ChallengeData struct {
	Address   string      `json:"address"`
	Username  string      `json:"username,omitempty"`
	IssuedAt  time.Time   `json:"issued_at"`
	ExpiresAt time.Time   `json:"expires_at"`
	Input     SignInInput `json:"input"` // Store full input for verification
}

// ChallengeCache stores pending SIWS challenges.
type ChallengeCache interface {
	Put(ctx context.Context, nonce string, data ChallengeData) error
	Get(ctx context.Context, nonce string) (ChallengeData, bool, error)
	Del(ctx context.Context, nonce string) error
}

// Verify checks that the signature is valid for the given input and output.
// Returns nil if valid, or an error describing the validation failure.
func Verify(input SignInInput, output SignInOutput) error {
	// Get public key from address
	pubKey, err := Base58ToPublicKey(output.Account.Address)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	// Verify the address in input matches output
	if input.Address != output.Account.Address {
		return fmt.Errorf("address mismatch: input=%s output=%s", input.Address, output.Account.Address)
	}

	// Construct the expected message from input
	expectedMessage := ConstructMessage(input)

	// The signed message should match what we expect
	if string(output.SignedMessage) != expectedMessage {
		return fmt.Errorf("signed message does not match expected message")
	}

	// Verify Ed25519 signature
	if !ed25519.Verify(pubKey, output.SignedMessage, output.Signature) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

// VerifySignature performs only cryptographic verification without message reconstruction.
// Use this when you trust the signedMessage bytes from the wallet.
func VerifySignature(output SignInOutput) error {
	pubKey, err := Base58ToPublicKey(output.Account.Address)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	if len(output.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: got %d, want %d", len(output.Signature), ed25519.SignatureSize)
	}

	if !ed25519.Verify(pubKey, output.SignedMessage, output.Signature) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

// Base58ToPublicKey decodes a base58-encoded Solana address to an Ed25519 public key.
func Base58ToPublicKey(address string) (ed25519.PublicKey, error) {
	decoded, err := base58.Decode(address)
	if err != nil {
		return nil, fmt.Errorf("base58 decode failed: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: got %d, want %d", len(decoded), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(decoded), nil
}

// PublicKeyToBase58 encodes an Ed25519 public key to a base58 Solana address.
func PublicKeyToBase58(pubKey ed25519.PublicKey) string {
	return base58.Encode(pubKey)
}

// ValidateAddress checks if a string is a valid Solana address.
func ValidateAddress(address string) error {
	_, err := Base58ToPublicKey(address)
	return err
}
