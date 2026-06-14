package jwtkit

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// AuthKit JOSE `typ` header values. These separate ordinary AuthKit access
// tokens from delegated access tokens before claims are mapped into principals.
const (
	AccessTokenType          = "access+jwt"
	DelegatedAccessTokenType = "delegated-access+jwt"
	// RemoteApplicationAccessTokenType is the JOSE `typ` for a JWKS principal's
	// SELF-token (#76): a remote_application signs a JWT whose subject is itself.
	// Distinct typ keeps the sub/delegated_sub invariant intact — a self-token
	// carries neither (identity is the validated `iss` -> remote_application).
	RemoteApplicationAccessTokenType = "remote-application-access+jwt"
)

// ClaimsBuilder builds custom claims layered on top of RegisteredClaims.
type ClaimsBuilder interface {
	// Build returns application-specific claims to embed.
	Build(ctx context.Context, userID string, base jwt.RegisteredClaims) (map[string]any, error)
}

// Signer issues and verifies asymmetric JWTs.
type Signer interface {
	// Algorithm returns the JWS algorithm (e.g., RS256, EdDSA).
	Algorithm() string
	// KID returns current key id.
	KID() string
	// Sign creates a signed JWT with provided claims.
	Sign(ctx context.Context, claims jwt.MapClaims) (token string, err error)
}

// HeaderSigner is an extension of Signer that lets callers set extra JOSE
// header parameters (e.g. `typ`) on the signed token. AuthKit token minting uses
// it to stamp the token profile header.
type HeaderSigner interface {
	Signer
	// SignWithHeaders signs claims and merges the provided extra JOSE header
	// params into the token header (kid is still set by the signer).
	SignWithHeaders(ctx context.Context, claims jwt.MapClaims, headers map[string]any) (token string, err error)
}

// Minimal in-memory RSA signer for bootstrap/dev. Production should load from KMS or DB.
type RSASigner struct {
	key *rsa.PrivateKey
	kid string
}

func NewRSASigner(bits int, kid string) (*RSASigner, error) {
	if bits == 0 {
		bits = 2048
	}
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return &RSASigner{key: k, kid: kid}, nil
}

func (s *RSASigner) Algorithm() string           { return jwt.SigningMethodRS256.Alg() }
func (s *RSASigner) KID() string                 { return s.kid }
func (s *RSASigner) PublicKey() crypto.PublicKey { return &s.key.PublicKey }
func (s *RSASigner) PrivateKey() *rsa.PrivateKey { return s.key }

func (s *RSASigner) Sign(_ context.Context, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid
	return token.SignedString(s.key)
}

// SignWithHeaders implements HeaderSigner: it signs claims and merges extra JOSE
// header params (e.g. `typ`) into the token header. The signer's own kid is set
// last and cannot be overridden by the supplied headers.
func (s *RSASigner) SignWithHeaders(_ context.Context, claims jwt.MapClaims, headers map[string]any) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	for k, val := range headers {
		if k == "kid" || k == "alg" {
			continue
		}
		token.Header[k] = val
	}
	token.Header["kid"] = s.kid
	return token.SignedString(s.key)
}

// NewRSASignerFromPEM constructs an RSASigner from a PEM-encoded RSA private key.
func NewRSASignerFromPEM(kid string, pemBytes []byte) (*RSASigner, error) {
	signer, err := NewSignerFromPEM(kid, pemBytes)
	if err != nil {
		return nil, err
	}
	r, ok := signer.(*RSASigner)
	if !ok {
		return nil, errors.New("pem is not RSA private key")
	}
	return r, nil
}

// Helper to make base registered claims.
func BaseRegisteredClaims(subject string, audiences []string, ttl time.Duration) jwt.RegisteredClaims {
	now := time.Now()
	return jwt.RegisteredClaims{
		Subject:   subject,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		Audience:  audiences,
	}
}
