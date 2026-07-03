package jwtkit

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	"testing"
)

func TestPublicToJWK_RSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := PublicToJWK(&key.PublicKey, "k1", "")
	if jwk.Kty != "RSA" || jwk.Alg != "RS256" || jwk.N == "" || jwk.E == "" {
		t.Fatalf("unexpected jwk: %+v", jwk)
	}
}

func TestPublicToJWK_EC(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := PublicToJWK(&key.PublicKey, "k1", "")
	if jwk.Kty != "EC" || jwk.Crv != "P-256" || jwk.X == "" || jwk.Y == "" {
		t.Fatalf("unexpected jwk: %+v", jwk)
	}
}

func TestPublicToJWK_Ed25519(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)
	jwk := PublicToJWK(pub, "k1", "")
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.X == "" {
		t.Fatalf("unexpected jwk: %+v", jwk)
	}
}

func TestJWKSToPublicKeys_EC_RoundTrip(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := PublicToJWK(&key.PublicKey, "ec1", "ES256")
	keys, err := JWKSToPublicKeys(JWKS{Keys: []JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := keys["ec1"].(*ecdsa.PublicKey); !ok {
		t.Fatalf("got %T", keys["ec1"])
	}
}

func TestJWKSToPublicKeys_UnsupportedKtyLoud(t *testing.T) {
	_, err := JWKSToPublicKeys(JWKS{Keys: []JWK{{Kty: "oct", Kid: "x"}}})
	if !errors.Is(err, ErrUnsupportedJWK) {
		t.Fatalf("got %v", err)
	}
}

func TestBase64URLCanonicalLeadingZeros(t *testing.T) {
	e := base64URLEncode(big.NewInt(65537))
	if e != "AQAB" {
		t.Fatalf("e = %q", e)
	}
}
