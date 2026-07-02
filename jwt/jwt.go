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

// AuthKit JOSE `typ` header values. These separate AuthKit JWT classes before
// claims are mapped into principals.
const (
	AccessTokenType          = "access+jwt"
	DelegatedAccessTokenType = "delegated-access+jwt"
	// RemoteApplicationAccessTokenType is the JOSE `typ` for a remote application
	// access token. It carries neither sub nor delegated_sub; identity is the
	// validated iss -> remote_application mapping.
	RemoteApplicationAccessTokenType = "remote-application-access+jwt"
)

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

// SignWithType signs claims, optionally stamping the JOSE `typ` header. It is the
// single home for the "assert HeaderSigner and set typ, or fall back" idiom that
// AuthKit's token-minting paths share:
//   - typ == "": plain Sign (no typ header).
//   - typ != "" && requireHeader: assert HeaderSigner; error if the signer can't
//     stamp headers.
//   - typ != "" && !requireHeader: stamp via HeaderSigner when available, else
//     fall back to a plain Sign.
func SignWithType(ctx context.Context, signer Signer, claims jwt.MapClaims, typ string, requireHeader bool) (string, error) {
	if typ == "" {
		return signer.Sign(ctx, claims)
	}
	hs, ok := signer.(HeaderSigner)
	if !ok {
		if requireHeader {
			return "", errors.New("header signer required")
		}
		return signer.Sign(ctx, claims)
	}
	return hs.SignWithHeaders(ctx, claims, map[string]any{"typ": typ})
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
	return signWithHeaders(jwt.SigningMethodRS256, s.key, s.kid, claims, nil)
}

// SignWithHeaders implements HeaderSigner: it signs claims and merges extra JOSE
// header params (e.g. `typ`) into the token header. The signer's own kid is set
// last and cannot be overridden by the supplied headers.
func (s *RSASigner) SignWithHeaders(_ context.Context, claims jwt.MapClaims, headers map[string]any) (string, error) {
	return signWithHeaders(jwt.SigningMethodRS256, s.key, s.kid, claims, headers)
}

// signWithHeaders is the shared signing body for every in-memory signer: build the
// token with the given method, merge any extra JOSE headers (kid/alg are reserved
// to the signer), stamp kid, and sign. The key is whatever crypto key the method
// expects (SignedString takes any).
func signWithHeaders(method jwt.SigningMethod, key any, kid string, claims jwt.MapClaims, headers map[string]any) (string, error) {
	token := jwt.NewWithClaims(method, claims)
	for k, val := range headers {
		if k == "kid" || k == "alg" {
			continue
		}
		token.Header[k] = val
	}
	token.Header["kid"] = kid
	return token.SignedString(key)
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
