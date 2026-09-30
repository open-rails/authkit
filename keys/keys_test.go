package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"testing"
	"time"
)

func TestNewStaticKeySourceFromPEM(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	ks, err := StaticFromPEM("static-kid", string(privPEM), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := ks.ActiveSigner().KID(); got != "static-kid" {
		t.Fatalf("active kid = %q, want static-kid", got)
	}
	if ks.PublicKeys()["static-kid"] == nil {
		t.Fatal("the active key is published")
	}
	if _, err := StaticFromPEM("static-kid", "", nil); err == nil {
		t.Fatal("expected error for missing private key PEM")
	}
	if _, err := StaticFromPEM("", string(privPEM), nil); err == nil {
		t.Fatal("expected error for missing active key ID")
	}
	if _, err := StaticFromPEM("static-kid", string(privPEM), map[string]string{"retired": "not pem"}); err == nil {
		t.Fatal("an unparseable rotation key is an error, never dropped")
	}
}

func TestNewFileKeySourceNeedsKeysJSON(t *testing.T) {
	if _, err := watch(t.TempDir(), time.Hour, slog.Default()); err == nil {
		t.Fatal("a directory without keys.json is an error")
	}
	if _, err := watch("", time.Hour, slog.Default()); err == nil {
		t.Fatal("an empty path is an error")
	}
}
