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

func TestResolveKeySourcePersistsDevKeysUnderExplicitPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	first, err := ResolveKeySource(dir, true)
	if err != nil {
		t.Fatalf("explicit ephemeral opt-in should generate dev keys: %v", err)
	}
	if first.ActiveSigner() == nil {
		t.Fatal("expected a generated active signer")
	}
	fi, err := os.Stat(filepath.Join(dir, "keys.json"))
	if err != nil {
		t.Fatalf("explicit path should persist keys.json: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("keys.json mode = %o, want 0600", fi.Mode().Perm())
	}
	second, err := ResolveKeySource(dir, true)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if first.ActiveSigner().KID() != second.ActiveSigner().KID() {
		t.Fatalf("expected persisted key to be reloaded: %q != %q",
			first.ActiveSigner().KID(), second.ActiveSigner().KID())
	}
}

// A generated dev key must never reach disk unless the caller named a path:
// the library has no business writing key material relative to the process cwd.
func TestResolveKeySourceDevKeysStayInMemoryWithoutPath(t *testing.T) {
	defaultKeys := filepath.Join(DefaultAuthKeysPath, "keys.json")
	if _, err := os.Stat(defaultKeys); err == nil {
		t.Skipf("%s exists on this host; the file branch would win", defaultKeys)
	}
	cwd := t.TempDir()
	t.Chdir(cwd)
	ks, err := ResolveKeySource("", true)
	if err != nil {
		t.Fatalf("ephemeral opt-in without a path should generate in memory: %v", err)
	}
	if _, ok := ks.(StaticKeySource); !ok {
		t.Fatalf("expected an in-memory StaticKeySource, got %T", ks)
	}
	entries, err := os.ReadDir(cwd)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("generated dev keys wrote into the cwd: %v", entries)
	}
	if _, err := os.Stat(defaultKeys); !os.IsNotExist(err) {
		t.Fatalf("generated dev keys wrote to %s (stat err=%v)", defaultKeys, err)
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
