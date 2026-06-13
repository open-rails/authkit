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

// clearKeyEnv unsets the key-related env vars and ENV for the duration of a test.
func clearKeyEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"ACTIVE_KEY_ID", "ACTIVE_PRIVATE_KEY_PEM", "PUBLIC_KEYS", "ENV", "APP_ENV", "ENVIRONMENT"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

func TestNewAutoKeySourceWithPathResolvesFile(t *testing.T) {
	clearKeyEnv(t)
	dir := t.TempDir()
	writeKeysJSON(t, dir, "file-kid-1")

	ks, err := NewAutoKeySourceWithPath(dir)
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
	clearKeyEnv(t)
	ks, err := FileKeySource(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("missing dir should not error: %v", err)
	}
	if ks != nil {
		t.Fatalf("expected nil KeySource for missing dir, got %T", ks)
	}
}

func TestEnvPrecedenceOverFile(t *testing.T) {
	clearKeyEnv(t)
	dir := t.TempDir()
	writeKeysJSON(t, dir, "file-kid")

	// Env key wins over the file key.
	envSigner, err := NewRSASigner(2048, "env-kid")
	if err != nil {
		t.Fatalf("env signer: %v", err)
	}
	envPEM := pemEncode("RSA PRIVATE KEY", x509MarshalPKCS1PrivateKey(envSigner.PrivateKey()))
	t.Setenv("ACTIVE_KEY_ID", "env-kid")
	t.Setenv("ACTIVE_PRIVATE_KEY_PEM", string(envPEM))

	ks, err := NewAutoKeySourceWithPath(dir)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := ks.ActiveSigner().KID(); got != "env-kid" {
		t.Fatalf("active kid = %q, want env-kid (env must win over file)", got)
	}
}

func TestProdHardFailsWithoutKey(t *testing.T) {
	clearKeyEnv(t)
	t.Setenv("ENV", "production")
	// Point at an empty dir so the file source falls through, and prod must NOT
	// auto-generate.
	_, err := NewAutoKeySourceWithPath(filepath.Join(t.TempDir(), "empty"))
	if err == nil {
		t.Fatal("expected hard-fail in production with no key, got nil error")
	}
}

func TestNonProdGeneratesFallback(t *testing.T) {
	clearKeyEnv(t)
	// No env, empty file dir, non-prod => dev-gen succeeds.
	ks, err := NewAutoKeySourceWithPath(filepath.Join(t.TempDir(), "empty"))
	if err != nil {
		t.Fatalf("non-prod should generate dev keys: %v", err)
	}
	if ks.ActiveSigner() == nil {
		t.Fatal("expected a generated active signer")
	}
}

func TestGeneratedKeySourceInDirPersists(t *testing.T) {
	dir := t.TempDir()
	first, err := NewGeneratedKeySourceInDir(dir)
	if err != nil {
		t.Fatalf("first gen: %v", err)
	}
	second, err := NewGeneratedKeySourceInDir(dir)
	if err != nil {
		t.Fatalf("second gen: %v", err)
	}
	if first.ActiveSigner().KID() != second.ActiveSigner().KID() {
		t.Fatalf("expected persisted key to be reloaded: %q != %q",
			first.ActiveSigner().KID(), second.ActiveSigner().KID())
	}
}

func TestSignerSignVerifyRoundTrip(t *testing.T) {
	clearKeyEnv(t)
	dir := t.TempDir()
	writeKeysJSON(t, dir, "rt-kid")
	ks, err := NewAutoKeySourceWithPath(dir)
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
