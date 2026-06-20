package jwtkit

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

func TestRSASignerRoundTrip(t *testing.T) {
	signer, err := NewRSASigner(2048, "rsa-kid")
	if err != nil {
		t.Fatal(err)
	}
	token, err := signer.Sign(context.Background(), jwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(tok *jwt.Token) (any, error) {
		return signer.PublicKey(), nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("parse failed: %v", err)
	}
}

func TestRemoteApplicationAccessTokenType(t *testing.T) {
	if RemoteApplicationAccessTokenType != "remote-application-access+jwt" {
		t.Fatalf("RemoteApplicationAccessTokenType = %q", RemoteApplicationAccessTokenType)
	}
}

func TestECDSASignerRoundTripES256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := newECDSASigner("ec-kid", key)
	if err != nil {
		t.Fatal(err)
	}
	verifySignerRoundTrip(t, signer)
}

func TestEd25519SignerRoundTrip(t *testing.T) {
	signer, err := NewEd25519Signer("ed-kid")
	if err != nil {
		t.Fatal(err)
	}
	verifySignerRoundTrip(t, signer)
}

func verifySignerRoundTrip(t *testing.T, signer Signer) {
	t.Helper()
	ps, ok := signer.(PublicKeySigner)
	if !ok {
		t.Fatal("signer must implement PublicKeySigner")
	}
	token, err := signer.Sign(context.Background(), jwt.MapClaims{
		"sub": "delegated-actor",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(tok *jwt.Token) (any, error) {
		return ps.PublicKey(), nil
	})
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestSignWithHeadersBlocksKidAlgOverride(t *testing.T) {
	signer, err := NewRSASigner(2048, "real-kid")
	if err != nil {
		t.Fatal(err)
	}
	token, err := signer.SignWithHeaders(context.Background(), jwt.MapClaims{"sub": "x"}, map[string]any{
		"kid": "evil",
		"alg": "none",
		"typ": "at+jwt",
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header["kid"] != "real-kid" {
		t.Fatalf("kid = %v", parsed.Header["kid"])
	}
	if parsed.Header["alg"] != "RS256" {
		t.Fatalf("alg = %v", parsed.Header["alg"])
	}
}

func TestNewSignerFromPEM(t *testing.T) {
	rsaSigner, _ := NewRSASigner(2048, "r")
	rsaPEM := pemEncodePrivateKey(rsaSigner.PrivateKey())

	signer, err := NewSignerFromPEM("r", rsaPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := signer.(*RSASigner); !ok {
		t.Fatalf("expected RSASigner, got %T", signer)
	}

	edSigner, err := NewEd25519Signer("e")
	if err != nil {
		t.Fatal(err)
	}
	edPEM, err := x509.MarshalPKCS8PrivateKey(edSigner.key)
	if err != nil {
		t.Fatal(err)
	}
	edBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: edPEM})
	signer2, err := NewSignerFromPEM("e", edBlock)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := signer2.(*Ed25519Signer); !ok {
		t.Fatalf("expected Ed25519Signer, got %T", signer2)
	}
}

func pemEncodePrivateKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func TestKeyRingMergesActiveKey(t *testing.T) {
	signer, _ := NewRSASigner(2048, "active")
	ring := NewKeyRing(signer, map[string]crypto.PublicKey{"retired": signer.PublicKey()})
	if ring.PublicKeys()["active"] == nil || ring.PublicKeys()["retired"] == nil {
		t.Fatalf("keys: %v", ring.PublicKeys())
	}
}

func TestTryLoadFromEnvPrecedence(t *testing.T) {
	rsaSigner, _ := NewRSASigner(2048, "env-kid")
	pemBytes := pemEncodePrivateKey(rsaSigner.PrivateKey())
	t.Setenv("ACTIVE_KEY_ID", "env-kid")
	t.Setenv("ACTIVE_PRIVATE_KEY_PEM", string(pemBytes))
	ks, err := tryLoadFromEnv()
	if err != nil || ks == nil {
		t.Fatalf("load: %v", err)
	}
	if ks.ActiveSigner().KID() != "env-kid" {
		t.Fatalf("kid %s", ks.ActiveSigner().KID())
	}
	_ = os.Unsetenv("ACTIVE_KEY_ID")
	_ = os.Unsetenv("ACTIVE_PRIVATE_KEY_PEM")
}
