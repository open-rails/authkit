package keys

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeKeysJSONWithRetired writes keys.json with the given active kid plus an
// optional public_keys map (retired verify-only keys). It returns the active
// signer's PKIX public-key PEM so a caller can chain it as a retired key in a
// later rotation.
func writeKeysJSONWithRetired(t *testing.T, dir, activeKID string, retired map[string]string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	pubs := map[string]string{}
	for k, v := range retired {
		pubs[k] = v
	}
	envelope := map[string]any{
		"active_key_id":          activeKID,
		"active_private_key_pem": string(privPEM),
		"public_keys":            pubs,
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keys.json"), data, 0600); err != nil {
		t.Fatalf("write keys.json: %v", err)
	}
	return pubPEM
}

func keysOf(m map[string]crypto.PublicKey) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Reload() picks up a rotated active key without a restart.
func TestReloadableReloadSwapsActiveKey(t *testing.T) {
	dir := t.TempDir()
	writeKeysJSONWithRetired(t, dir, "kid-A", nil)

	ks, err := watch(dir, time.Hour, slog.Default()) // long interval; drive Reload() directly
	if err != nil {
		t.Fatalf("new reloadable: %v", err)
	}
	defer ks.Close()
	if got := ks.ActiveSigner().KID(); got != "kid-A" {
		t.Fatalf("active kid = %q, want kid-A", got)
	}

	writeKeysJSONWithRetired(t, dir, "kid-B", nil)
	if err := ks.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := ks.ActiveSigner().KID(); got != "kid-B" {
		t.Fatalf("after reload active kid = %q, want kid-B", got)
	}
}

// A malformed / partial keys.json must error AND keep the last-good keystore —
// a bad Vault render never bricks signing.
func TestReloadableKeepsOldOnMalformed(t *testing.T) {
	dir := t.TempDir()
	writeKeysJSONWithRetired(t, dir, "kid-good", nil)

	ks, err := watch(dir, time.Hour, slog.Default())
	if err != nil {
		t.Fatalf("new reloadable: %v", err)
	}
	defer ks.Close()

	keysFile := filepath.Join(dir, "keys.json")

	if err := os.WriteFile(keysFile, []byte("{not json"), 0600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	if err := ks.Reload(); err == nil {
		t.Fatal("expected reload error on malformed keys.json")
	}
	if got := ks.ActiveSigner().KID(); got != "kid-good" {
		t.Fatalf("active kid = %q, want kid-good retained after malformed reload", got)
	}

	// Missing active_private_key_pem -> error -> keep old.
	if err := os.WriteFile(keysFile, []byte(`{"active_key_id":"x"}`), 0600); err != nil {
		t.Fatalf("write partial: %v", err)
	}
	if err := ks.Reload(); err == nil {
		t.Fatal("expected reload error on keys.json missing private key")
	}
	if got := ks.ActiveSigner().KID(); got != "kid-good" {
		t.Fatalf("active kid = %q, want kid-good retained after partial reload", got)
	}
}

// The background poller swaps the key in after the file changes.
func TestReloadablePollerPicksUpChange(t *testing.T) {
	dir := t.TempDir()
	writeKeysJSONWithRetired(t, dir, "kid-1", nil)

	ks, err := watch(dir, 10*time.Millisecond, slog.Default())
	if err != nil {
		t.Fatalf("new reloadable: %v", err)
	}
	defer ks.Close()

	writeKeysJSONWithRetired(t, dir, "kid-2", nil)
	// Force a clearly-later mtime so change detection fires regardless of the
	// filesystem's mtime resolution.
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(filepath.Join(dir, "keys.json"), future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ks.ActiveSigner().KID() == "kid-2" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("poller did not pick up kid-2 within deadline; active=%q", ks.ActiveSigner().KID())
}

// After rotation the retired key stays in JWKS so ≤TTL in-flight tokens still
// verify, while new tokens are signed by (and verify against) the new key.
func TestReloadableRetainsRetiredPublicKey(t *testing.T) {
	dir := t.TempDir()
	oldPubPEM := writeKeysJSONWithRetired(t, dir, "kid-old", nil)

	ks, err := watch(dir, time.Hour, slog.Default())
	if err != nil {
		t.Fatalf("new reloadable: %v", err)
	}
	defer ks.Close()

	// Rotate: new active key, retire the old one into public_keys.
	writeKeysJSONWithRetired(t, dir, "kid-new", map[string]string{"kid-old": oldPubPEM})
	if err := ks.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	pubs := ks.PublicKeys()
	if _, ok := pubs["kid-new"]; !ok {
		t.Fatalf("JWKS missing new active key; have %v", keysOf(pubs))
	}
	if _, ok := pubs["kid-old"]; !ok {
		t.Fatalf("JWKS missing retired key kid-old (in-flight tokens would fail); have %v", keysOf(pubs))
	}

	input := []byte("header.payload")
	sig, err := ks.ActiveSigner().Sign(context.Background(), input)
	if err != nil {
		t.Fatalf("sign with new key: %v", err)
	}
	digest := sha256.Sum256(input)
	if err := rsa.VerifyPKCS1v15(pubs["kid-new"].(*rsa.PublicKey), crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("verify new-key signature against JWKS: %v", err)
	}
}
