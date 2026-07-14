package jwtkit

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"strings"
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

// PayloadSigner is the optional Signer extension for compact JWS payloads that
// must be signed byte-for-byte. Unlike Sign, it does not marshal a MapClaims.
// AuthKit's built-in RSA, ECDSA, and Ed25519 signers implement it.
type PayloadSigner interface {
	Signer
	SignPayload(ctx context.Context, payload []byte, headers map[string]any) (token string, err error)
}

// ErrPayloadSignerRequired means a Signer can issue JWT claims but cannot sign
// an exact caller-supplied JWS payload.
var ErrPayloadSignerRequired = errors.New("payload signer required")

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

// SignPayloadWithType signs payload exactly as supplied and stamps typ. It is
// used for signed documents, whose digest covers the same bytes carried by the
// compact JWS payload.
func SignPayloadWithType(ctx context.Context, signer Signer, payload []byte, typ string) (string, error) {
	ps, ok := signer.(PayloadSigner)
	if !ok {
		return "", ErrPayloadSignerRequired
	}
	return ps.SignPayload(ctx, payload, map[string]any{"typ": typ})
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

func (s *RSASigner) SignPayload(_ context.Context, payload []byte, headers map[string]any) (string, error) {
	return signWithHeaders(jwt.SigningMethodRS256, s.key, s.kid, exactClaims{payload: payload}, headers)
}

// signWithHeaders is the shared signing body for every in-memory signer: build the
// token with the given method, merge any extra JOSE headers (kid/alg are reserved
// to the signer), stamp kid, and sign. The key is whatever crypto key the method
// expects (SignedString takes any).
func signWithHeaders(method jwt.SigningMethod, key any, kid string, claims jwt.Claims, headers map[string]any) (string, error) {
	if kid == "" || kid != strings.TrimSpace(kid) {
		return "", errors.New("signer kid required")
	}
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

// exactClaims lets golang-jwt build and sign the JOSE header/signing input while
// preserving an already-marshaled payload byte-for-byte.
type exactClaims struct{ payload []byte }

func (c exactClaims) MarshalJSON() ([]byte, error) {
	if !json.Valid(c.payload) {
		return nil, errors.New("invalid json payload")
	}
	return append([]byte(nil), c.payload...), nil
}
func (exactClaims) GetExpirationTime() (*jwt.NumericDate, error) { return nil, nil }
func (exactClaims) GetIssuedAt() (*jwt.NumericDate, error)       { return nil, nil }
func (exactClaims) GetNotBefore() (*jwt.NumericDate, error)      { return nil, nil }
func (exactClaims) GetIssuer() (string, error)                   { return "", nil }
func (exactClaims) GetSubject() (string, error)                  { return "", nil }
func (exactClaims) GetAudience() (jwt.ClaimStrings, error)       { return nil, nil }

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
