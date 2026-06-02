package siws

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/mr-tron/base58"
)

// ConstructMessage builds the SIWS message following the ABNF specification.
// The message format is:
//
//	${domain} wants you to sign in with your Solana account:
//	${address}
//
//	${statement}
//
//	URI: ${uri}
//	Version: ${version}
//	Chain ID: ${chainId}
//	Nonce: ${nonce}
//	Issued At: ${issuedAt}
//	Expiration Time: ${expirationTime}
//	Not Before: ${notBefore}
//	Request ID: ${requestId}
//	Resources:
//	- ${resources[0]}
//	- ${resources[1]}
//	...
func ConstructMessage(input SignInInput) string {
	var sb strings.Builder

	// Required header
	sb.WriteString(input.Domain)
	sb.WriteString(" wants you to sign in with your Solana account:\n")
	sb.WriteString(input.Address)

	// Statement (with blank line before if present)
	if input.Statement != nil && *input.Statement != "" {
		sb.WriteString("\n\n")
		sb.WriteString(*input.Statement)
	}

	// Fields section (blank line before)
	sb.WriteString("\n")

	// URI
	if input.URI != nil && *input.URI != "" {
		sb.WriteString("\nURI: ")
		sb.WriteString(*input.URI)
	}

	// Version
	if input.Version != nil && *input.Version != "" {
		sb.WriteString("\nVersion: ")
		sb.WriteString(*input.Version)
	}

	// Chain ID
	if input.ChainID != nil && *input.ChainID != "" {
		sb.WriteString("\nChain ID: ")
		sb.WriteString(*input.ChainID)
	}

	// Nonce (required)
	sb.WriteString("\nNonce: ")
	sb.WriteString(input.Nonce)

	// Issued At (required)
	sb.WriteString("\nIssued At: ")
	sb.WriteString(input.IssuedAt)

	// Expiration Time
	if input.ExpirationTime != nil && *input.ExpirationTime != "" {
		sb.WriteString("\nExpiration Time: ")
		sb.WriteString(*input.ExpirationTime)
	}

	// Not Before
	if input.NotBefore != nil && *input.NotBefore != "" {
		sb.WriteString("\nNot Before: ")
		sb.WriteString(*input.NotBefore)
	}

	// Request ID
	if input.RequestID != nil && *input.RequestID != "" {
		sb.WriteString("\nRequest ID: ")
		sb.WriteString(*input.RequestID)
	}

	// Resources
	if len(input.Resources) > 0 {
		sb.WriteString("\nResources:")
		for _, r := range input.Resources {
			sb.WriteString("\n- ")
			sb.WriteString(r)
		}
	}

	return sb.String()
}

// GenerateNonce creates a cryptographically secure random nonce.
// The nonce is base58-encoded so it is purely alphanumeric, as required by the
// SIWS / EIP-4361 ABNF (nonce = 8*( ALPHA / DIGIT )). base64url is unsuitable
// because its alphabet includes '-' and '_', which strict wallets reject.
// 16 random bytes (128 bits of entropy) encode to ~22 alphanumeric characters,
// comfortably above the 8-character minimum.
func GenerateNonce() (string, error) {
	b := make([]byte, 16) // 16 bytes = 128 bits of entropy
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	return base58.Encode(b), nil
}

// NewSignInInput creates a SignInInput with required fields and sensible defaults.
func NewSignInInput(domain, address string, opts ...InputOption) (SignInInput, error) {
	nonce, err := GenerateNonce()
	if err != nil {
		return SignInInput{}, err
	}

	now := time.Now().UTC()
	issuedAt := now.Format(time.RFC3339)
	expirationTime := now.Add(15 * time.Minute).Format(time.RFC3339)

	version := "1"
	chainID := "mainnet"

	input := SignInInput{
		Domain:         domain,
		Address:        address,
		Nonce:          nonce,
		IssuedAt:       issuedAt,
		ExpirationTime: &expirationTime,
		Version:        &version,
		ChainID:        &chainID,
	}

	for _, opt := range opts {
		opt(&input)
	}

	return input, nil
}

// InputOption is a functional option for customizing SignInInput.
type InputOption func(*SignInInput)

// WithStatement sets a custom statement message.
func WithStatement(statement string) InputOption {
	return func(i *SignInInput) {
		i.Statement = &statement
	}
}

// WithURI sets the URI field.
func WithURI(uri string) InputOption {
	return func(i *SignInInput) {
		i.URI = &uri
	}
}

// WithChainID sets a custom chain ID (mainnet, devnet, testnet).
func WithChainID(chainID string) InputOption {
	return func(i *SignInInput) {
		i.ChainID = &chainID
	}
}

// WithExpirationDuration sets expiration relative to issued time.
func WithExpirationDuration(d time.Duration) InputOption {
	return func(i *SignInInput) {
		// Parse IssuedAt to calculate expiration
		issuedAt, err := time.Parse(time.RFC3339, i.IssuedAt)
		if err != nil {
			issuedAt = time.Now().UTC()
		}
		exp := issuedAt.Add(d).Format(time.RFC3339)
		i.ExpirationTime = &exp
	}
}

// WithResources adds resource URIs to the input.
func WithResources(resources ...string) InputOption {
	return func(i *SignInInput) {
		i.Resources = append(i.Resources, resources...)
	}
}
