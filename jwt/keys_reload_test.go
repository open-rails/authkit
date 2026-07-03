package jwtkit

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// writeKeysJSONWithRetired writes keys.json with the given active kid plus an
// optional public_keys map (retired verify-only keys). It returns the active
// signer's PKIX public-key PEM so a caller can chain it as a retired key in a
// later rotation.
func writeKeysJSONWithRetired(t *testing.T, dir, activeKID string, retired map[string]string) string {
	t.Helper()
	signer, err := NewRSASigner(2048, activeKID)
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	privPEM := pemEncode("RSA PRIVATE KEY", x509MarshalPKCS1PrivateKey(signer.PrivateKey()))
	der, err := x509.MarshalPKIXPublicKey(signer.PublicKey())
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	pubPEM := string(pemEncode("PUBLIC KEY", der))

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
	writeKeysJSON(t, dir, "kid-A")

	ks, err := NewReloadableFileKeySource(dir, time.Hour) // long interval; drive Reload() directly
	if err != nil {
		t.Fatalf("new reloadable: %v", err)
	}
	defer ks.Close()
	if got := ks.ActiveSigner().KID(); got != "kid-A" {
		t.Fatalf("active kid = %q, want kid-A", got)
	}

	writeKeysJSON(t, dir, "kid-B")
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
	writeKeysJSON(t, dir, "kid-good")

	ks, err := NewReloadableFileKeySource(dir, time.Hour)
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
	writeKeysJSON(t, dir, "kid-1")

	ks, err := NewReloadableFileKeySource(dir, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("new reloadable: %v", err)
	}
	defer ks.Close()

	writeKeysJSON(t, dir, "kid-2")
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

	ks, err := NewReloadableFileKeySource(dir, time.Hour)
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

	tok, err := ks.ActiveSigner().Sign(context.Background(), jwt.MapClaims{"sub": "u1"})
	if err != nil {
		t.Fatalf("sign with new key: %v", err)
	}
	if _, err := jwt.Parse(tok, func(*jwt.Token) (any, error) { return pubs["kid-new"], nil }); err != nil {
		t.Fatalf("verify new-key token against JWKS: %v", err)
	}
}
