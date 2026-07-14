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

// ecdsaSigner signs JWTs with ES256, ES384, or ES512 based on the private key curve.
type ecdsaSigner struct {
	key *ecdsa.PrivateKey
	kid string
	alg string
}

func newECDSASigner(kid string, key *ecdsa.PrivateKey) (*ecdsaSigner, error) {
	if key == nil {
		return nil, errors.New("nil ecdsa private key")
	}
	alg, err := ecdsaAlgorithm(key)
	if err != nil {
		return nil, err
	}
	return &ecdsaSigner{key: key, kid: kid, alg: alg}, nil
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

func (s *ecdsaSigner) signingMethod() jwt.SigningMethod {
	switch s.alg {
	case jwt.SigningMethodES384.Alg():
		return jwt.SigningMethodES384
	case jwt.SigningMethodES512.Alg():
		return jwt.SigningMethodES512
	default:
		return jwt.SigningMethodES256
	}
}

func (s *ecdsaSigner) Algorithm() string { return s.alg }
func (s *ecdsaSigner) KID() string       { return s.kid }
func (s *ecdsaSigner) PublicKey() crypto.PublicKey {
	return &s.key.PublicKey
}

func (s *ecdsaSigner) Sign(_ context.Context, claims jwt.MapClaims) (string, error) {
	return signWithHeaders(s.signingMethod(), s.key, s.kid, claims, nil)
}

func (s *ecdsaSigner) SignWithHeaders(_ context.Context, claims jwt.MapClaims, headers map[string]any) (string, error) {
	return signWithHeaders(s.signingMethod(), s.key, s.kid, claims, headers)
}

func (s *ecdsaSigner) SignPayload(_ context.Context, payload []byte, headers map[string]any) (string, error) {
	return signWithHeaders(s.signingMethod(), s.key, s.kid, exactClaims{payload: payload}, headers)
}
