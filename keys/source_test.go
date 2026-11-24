package keys_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-rails/authkit/keys"
)

func TestStaticFromPEMActiveKID(t *testing.T) {
	active, other := rsaPEM(t), rsaPEM(t)
	cases := []struct {
		name   string
		public map[string]string
		ok     bool
	}{
		{"active key alone", nil, true},
		{"active kid with its own public key", map[string]string{"active": active.public}, true},
		{"retired kid", map[string]string{"retired": other.public}, true},
		{"active kid with another key", map[string]string{"active": other.public}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := keys.StaticFromPEM("active", active.private, c.public)
			if (err == nil) != c.ok {
				t.Fatalf("err = %v, want ok %v", err, c.ok)
			}
			if err != nil {
				return
			}
			pub, ok := s.PublicKeys()["active"].(*rsa.PublicKey)
			if !ok || !pub.Equal(s.ActiveSigner().Public()) {
				t.Fatal("JWKS does not publish the active signer's own key")
			}
		})
	}
}

type pemPair struct{ private, public string }

func rsaPEM(t *testing.T) pemPair {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pemPair{
		private: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		public:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})),
	}
}

func TestReloadNeverSwapsDevelopmentKeysForProvisioned(t *testing.T) {
	dir := t.TempDir()
	write := func(kid string, development bool) {
		t.Helper()
		data, err := json.Marshal(map[string]any{"active_key_id": kid, "active_private_key_pem": rsaPEM(t).private, "development": development})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "keys.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("provisioned", false)
	src, err := keys.Watch(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if src.Development() {
		t.Fatal("unmarked keys.json reported as development")
	}
	write("development", true)
	if err := src.Reload(); err == nil || src.ActiveSigner().KID() != "provisioned" || src.Development() {
		t.Fatalf("development keys replaced provisioned ones: %v", err)
	}

	write("development", true)
	dev, err := keys.Watch(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if !dev.Development() {
		t.Fatal("marked keys.json not reported as development")
	}
	write("provisioned", false)
	if err := dev.Reload(); err != nil || dev.Development() || dev.ActiveSigner().KID() != "provisioned" {
		t.Fatalf("provisioned keys did not replace development ones: %v", err)
	}
}
