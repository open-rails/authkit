package jwtkit

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"

	jwt "github.com/golang-jwt/jwt/v5"
)

// ECDSASigner signs JWTs with ES256, ES384, or ES512 based on the private key curve.
type ECDSASigner struct {
	key *ecdsa.PrivateKey
	kid string
	alg string
}

func newECDSASigner(kid string, key *ecdsa.PrivateKey) (*ECDSASigner, error) {
	if key == nil {
		return nil, errors.New("nil ecdsa private key")
	}
	alg, err := ecdsaAlgorithm(key)
	if err != nil {
		return nil, err
	}
	return &ECDSASigner{key: key, kid: kid, alg: alg}, nil
}

func ecdsaAlgorithm(key *ecdsa.PrivateKey) (string, error) {
	switch key.Curve {
	case elliptic.P256():
		return jwt.SigningMethodES256.Alg(), nil
	case elliptic.P384():
		return jwt.SigningMethodES384.Alg(), nil
	case elliptic.P521():
		return jwt.SigningMethodES512.Alg(), nil
	default:
		return "", fmt.Errorf("unsupported ecdsa curve %s", key.Curve.Params().Name)
	}
}

func (s *ECDSASigner) signingMethod() jwt.SigningMethod {
	switch s.alg {
	case jwt.SigningMethodES384.Alg():
		return jwt.SigningMethodES384
	case jwt.SigningMethodES512.Alg():
		return jwt.SigningMethodES512
	default:
		return jwt.SigningMethodES256
	}
}

func (s *ECDSASigner) Algorithm() string { return s.alg }
func (s *ECDSASigner) KID() string       { return s.kid }
func (s *ECDSASigner) PublicKey() crypto.PublicKey {
	return &s.key.PublicKey
}

func (s *ECDSASigner) Sign(_ context.Context, claims jwt.MapClaims) (string, error) {
	return signWithHeaders(s.signingMethod(), s.key, s.kid, claims, nil)
}

func (s *ECDSASigner) SignWithHeaders(_ context.Context, claims jwt.MapClaims, headers map[string]any) (string, error) {
	return signWithHeaders(s.signingMethod(), s.key, s.kid, claims, headers)
}
