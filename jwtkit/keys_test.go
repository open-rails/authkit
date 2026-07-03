package jwtkit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
)

// writeKeysJSON writes a {active_key_id, active_private_key_pem, public_keys}
// envelope into dir/keys.json and returns the active key id used.
func writeKeysJSON(t *testing.T, dir, kid string) {
	t.Helper()
	signer, err := NewRSASigner(2048, kid)
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	privPEM := pemEncode("RSA PRIVATE KEY", x509MarshalPKCS1PrivateKey(signer.PrivateKey()))

	envelope := map[string]any{
		"active_key_id":          kid,
		"active_private_key_pem": string(privPEM),
		"public_keys":            map[string]string{},
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keys.json"), data, 0600); err != nil {
		t.Fatalf("write keys.json: %v", err)
	}
}

func TestResolveKeySourceResolvesFile(t *testing.T) {
	dir := t.TempDir()
	writeKeysJSON(t, dir, "file-kid-1")

	ks, err := ResolveKeySource(dir, false)
	if err != nil {
		t.Fatalf("resolve from path: %v", err)
	}
	if got := ks.ActiveSigner().KID(); got != "file-kid-1" {
		t.Fatalf("active kid = %q, want file-kid-1", got)
	}
	if _, ok := ks.PublicKeys()["file-kid-1"]; !ok {
		t.Fatalf("JWKS missing public key for active kid; have %v", ks.PublicKeys())
	}
}

func TestFileKeySourceMissingReturnsNil(t *testing.T) {
	ks, err := tryLoadFromFilesystem(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("missing dir should not error: %v", err)
	}
	if ks != nil {
		t.Fatalf("expected nil KeySource for missing dir, got %T", ks)
	}
}

func TestNewStaticKeySourceFromPEM(t *testing.T) {
	signer, err := NewRSASigner(2048, "static-kid")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	privPEM := pemEncode("RSA PRIVATE KEY", x509MarshalPKCS1PrivateKey(signer.PrivateKey()))

	ks, err := NewStaticKeySourceFromPEM("static-kid", string(privPEM), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := ks.ActiveSigner().KID(); got != "static-kid" {
		t.Fatalf("active kid = %q, want static-kid", got)
	}

	// Both halves are required — mismatched material is a hard error.
	if _, err := NewStaticKeySourceFromPEM("static-kid", "", nil); err == nil {
		t.Fatal("expected error for missing private key PEM")
	}
	if _, err := NewStaticKeySourceFromPEM("", string(privPEM), nil); err == nil {
		t.Fatal("expected error for missing active key ID")
	}
}

func TestResolveKeySourceFailsClosedWithoutOptIn(t *testing.T) {
	// Empty dir, no ephemeral opt-in => hard error, never auto-generate (#231).
	_, err := ResolveKeySource(filepath.Join(t.TempDir(), "empty"), false)
	if err == nil {
		t.Fatal("expected hard-fail with no key and no ephemeral opt-in, got nil error")
	}
}

func TestResolveKeySourceGeneratesWithOptIn(t *testing.T) {
	// Generated keys persist under .runtime/authkit relative to CWD; isolate.
	t.Chdir(t.TempDir())
	ks, err := ResolveKeySource(filepath.Join(t.TempDir(), "empty"), true)
	if err != nil {
		t.Fatalf("explicit ephemeral opt-in should generate dev keys: %v", err)
	}
	if ks.ActiveSigner() == nil {
		t.Fatal("expected a generated active signer")
	}
}

func TestGeneratedKeySourceInDirPersists(t *testing.T) {
	dir := t.TempDir()
	first, err := newGeneratedKeySourceInDir(dir)
	if err != nil {
		t.Fatalf("first gen: %v", err)
	}
	second, err := newGeneratedKeySourceInDir(dir)
	if err != nil {
		t.Fatalf("second gen: %v", err)
	}
	if first.ActiveSigner().KID() != second.ActiveSigner().KID() {
		t.Fatalf("expected persisted key to be reloaded: %q != %q",
			first.ActiveSigner().KID(), second.ActiveSigner().KID())
	}
}

func TestSignerSignVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	writeKeysJSON(t, dir, "rt-kid")
	ks, err := ResolveKeySource(dir, false)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	tok, err := ks.ActiveSigner().Sign(context.Background(), jwt.MapClaims{"sub": "u1"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	pub := ks.PublicKeys()["rt-kid"]
	parsed, err := jwt.Parse(tok, func(*jwt.Token) (any, error) { return pub, nil })
	if err != nil || !parsed.Valid {
		t.Fatalf("verify against JWKS failed: %v", err)
	}
}
