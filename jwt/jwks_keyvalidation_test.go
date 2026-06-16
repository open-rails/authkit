package jwtkit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
)

func TestJWKToPublicKey_RSARejectsWeakModulus(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024) // below the 2048 floor
	if err != nil {
		t.Fatal(err)
	}
	jwk := RSAPublicToJWK(&weak.PublicKey, "weak", "RS256")
	if _, err := JWKToPublicKey(jwk); err == nil {
		t.Fatal("expected 1024-bit RSA key to be rejected")
	}
}

func TestJWKToPublicKey_RSAAcceptsStrongModulus(t *testing.T) {
	strong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := RSAPublicToJWK(&strong.PublicKey, "ok", "RS256")
	if _, err := JWKToPublicKey(jwk); err != nil {
		t.Fatalf("expected 2048-bit RSA key to be accepted, got %v", err)
	}
}

func TestJWKToPublicKey_RSARejectsEvenExponent(t *testing.T) {
	strong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := RSAPublicToJWK(&strong.PublicKey, "bad-e", "RS256")
	jwk.E = base64.RawURLEncoding.EncodeToString(big.NewInt(4).Bytes()) // even, invalid
	if _, err := JWKToPublicKey(jwk); err == nil {
		t.Fatal("expected even RSA exponent to be rejected")
	}
}

func TestJWKToPublicKey_ECAcceptsValidPoint(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := PublicToJWK(&priv.PublicKey, "ec", "ES256")
	if _, err := JWKToPublicKey(jwk); err != nil {
		t.Fatalf("expected valid P-256 key to be accepted, got %v", err)
	}
}

func TestJWKToPublicKey_ECRejectsOffCurvePoint(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := PublicToJWK(&priv.PublicKey, "ec", "ES256")
	// Corrupt Y so the point no longer lies on the curve.
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		t.Fatal(err)
	}
	yBytes[len(yBytes)-1] ^= 0x01
	jwk.Y = base64.RawURLEncoding.EncodeToString(yBytes)
	if _, err := JWKToPublicKey(jwk); err == nil {
		t.Fatal("expected off-curve EC point to be rejected")
	}
}

func TestValidateRSAPublicKey_NilSafe(t *testing.T) {
	if err := validateRSAPublicKey(nil); err == nil {
		t.Fatal("expected error for nil key")
	}
	if err := validateRSAPublicKey(&rsa.PublicKey{N: nil}); err == nil {
		t.Fatal("expected error for nil modulus")
	}
}

func TestValidateECPublicKeyOnCurve_NilSafe(t *testing.T) {
	if err := validateECPublicKeyOnCurve(nil); err == nil {
		t.Fatal("expected error for nil key")
	}
	if err := validateECPublicKeyOnCurve(&ecdsa.PublicKey{Curve: elliptic.P256()}); err == nil {
		t.Fatal("expected error for missing coordinates")
	}
	_ = errors.New
}
