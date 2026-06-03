package jwtkit

import (
	"context"
	"crypto"
	"crypto/ed25519"

	jwt "github.com/golang-jwt/jwt/v5"
)

// Ed25519Signer signs JWTs with EdDSA (Ed25519).
type Ed25519Signer struct {
	key ed25519.PrivateKey
	kid string
}

// NewEd25519Signer generates a new Ed25519 key pair for development/testing.
func NewEd25519Signer(kid string) (*Ed25519Signer, error) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return &Ed25519Signer{key: priv, kid: kid}, nil
}

func (s *Ed25519Signer) Algorithm() string { return jwt.SigningMethodEdDSA.Alg() }
func (s *Ed25519Signer) KID() string       { return s.kid }
func (s *Ed25519Signer) PublicKey() crypto.PublicKey {
	return s.key.Public().(ed25519.PublicKey)
}

func (s *Ed25519Signer) Sign(_ context.Context, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = s.kid
	return token.SignedString(s.key)
}

func (s *Ed25519Signer) SignWithHeaders(_ context.Context, claims jwt.MapClaims, headers map[string]any) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	for k, val := range headers {
		if k == "kid" || k == "alg" {
			continue
		}
		token.Header[k] = val
	}
	token.Header["kid"] = s.kid
	return token.SignedString(s.key)
}
