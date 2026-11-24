package authkit_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-rails/authkit"
)

// Development keys are generated, persisted and reused only for a loopback
// issuer; every other issuer needs provisioned keys and refuses marked ones.
// No database: authkit.New resolves keys before it touches one.

const (
	localIssuer      = "http://localhost:4780"
	productionIssuer = "https://auth.example.com"
)

type devKeyBoot struct {
	client *authkit.Client
	err    error
	logs   string
}

func bootKeys(t *testing.T, issuer string, keys authkit.KeysConfig) devKeyBoot {
	t.Helper()
	var logs bytes.Buffer
	cfg := authkit.Config{Token: authkit.TokenConfig{Issuer: issuer, IssuedAudiences: []string{"app"}}, Keys: keys}
	client, err := authkit.New(context.Background(), cfg, authkit.Deps{Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if client != nil {
		t.Cleanup(func() { _ = client.Close(context.Background()) })
	}
	return devKeyBoot{client, err, logs.String()}
}

func (b devKeyBoot) developmentLines() int {
	return strings.Count(b.logs, "signing with development keys")
}

func mustBoot(t *testing.T, b devKeyBoot) devKeyBoot {
	t.Helper()
	if b.err != nil {
		t.Fatalf("New: %v", b.err)
	}
	return b
}

func readKey(t *testing.T, dir, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeKey(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func provisionedKeysJSON(t *testing.T, development bool) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{
		"active_key_id":          "provisioned",
		"active_private_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		"public_keys":            map[string]string{},
		"development":            development,
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertDevelopmentKeys(t *testing.T, dir string) {
	t.Helper()
	var envelope struct{ Development bool }
	if err := json.Unmarshal(readKey(t, dir, "keys.json"), &envelope); err != nil || !envelope.Development {
		t.Fatalf("generated keys.json is not marked development: %v", err)
	}
	if !strings.HasPrefix(string(readKey(t, dir, "totp.key")), "development:") {
		t.Fatal("generated totp.key is not marked development")
	}
}

func TestLoopbackIssuerGeneratesPersistsAndReusesDevelopmentKeys(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	id := sha256.Sum256([]byte(localIssuer))
	dir := filepath.Join(state, "authkit", "development", hex.EncodeToString(id[:]))

	first := mustBoot(t, bootKeys(t, localIssuer, authkit.KeysConfig{}))
	assertDevelopmentKeys(t, dir)
	if first.developmentLines() != 1 || !strings.Contains(first.logs, dir) {
		t.Fatalf("want one INFO line naming %s, got:\n%s", dir, first.logs)
	}
	signing, totp := readKey(t, dir, "keys.json"), readKey(t, dir, "totp.key")
	noErr(t, first.client.Close(context.Background()))

	again := mustBoot(t, bootKeys(t, localIssuer, authkit.KeysConfig{}))
	if !bytes.Equal(signing, readKey(t, dir, "keys.json")) || !bytes.Equal(totp, readKey(t, dir, "totp.key")) {
		t.Fatal("restart regenerated development keys")
	}
	if again.developmentLines() != 1 || !strings.Contains(again.logs, "generated=[]") {
		t.Fatalf("restart should log reuse, not generation:\n%s", again.logs)
	}

	other := mustBoot(t, bootKeys(t, "http://127.0.0.1:9000", authkit.KeysConfig{}))
	if strings.Contains(other.logs, dir) {
		t.Fatal("another loopback issuer shared the directory")
	}
}

func TestLoopbackIssuerGeneratesIntoConfiguredPath(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	dir := filepath.Join(t.TempDir(), "vault", "auth")
	for _, issuer := range []string{localIssuer, "http://127.0.0.1:4780/auth", "http://[::1]:4780"} {
		b := mustBoot(t, bootKeys(t, issuer, authkit.KeysConfig{Path: dir}))
		assertDevelopmentKeys(t, dir)
		if b.developmentLines() != 1 || !strings.Contains(b.logs, dir) {
			t.Fatalf("%s: want one INFO line naming %s:\n%s", issuer, dir, b.logs)
		}
	}
}

func TestNonLoopbackIssuerNeverGenerates(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	dir := t.TempDir()
	for _, issuer := range []string{productionIssuer, "https://10.0.0.5:8443", "https://localhost.example.com"} {
		b := bootKeys(t, issuer, authkit.KeysConfig{Path: dir})
		if b.err == nil || !strings.Contains(b.err.Error(), "keys.json not found; mount keys.json or provide Deps.KeySource") {
			t.Fatalf("%s: New = %v, want a missing keys.json refusal", issuer, b.err)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("a non-loopback issuer wrote %d files", len(entries))
	}
}

func TestProvisionedKeysAreUsedNeverRegenerated(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	for _, issuer := range []string{localIssuer, productionIssuer} {
		dir := t.TempDir()
		signing := provisionedKeysJSON(t, false)
		writeKey(t, dir, "keys.json", signing)
		writeKey(t, dir, "totp.key", []byte(hex.EncodeToString(make([]byte, 32))))
		b := mustBoot(t, bootKeys(t, issuer, authkit.KeysConfig{Path: dir}))
		if b.developmentLines() != 0 || !bytes.Equal(signing, readKey(t, dir, "keys.json")) {
			t.Fatalf("%s: provisioned keys were replaced or reported as development:\n%s", issuer, b.logs)
		}
	}
}

func TestDevelopmentKeysSignOnlyForLoopbackIssuers(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	dir := t.TempDir()
	mustBoot(t, bootKeys(t, localIssuer, authkit.KeysConfig{Path: dir}))

	b := bootKeys(t, productionIssuer, authkit.KeysConfig{Path: dir})
	if b.err == nil || !strings.Contains(b.err.Error(), "development keys cannot sign for "+productionIssuer+": provision real keys") {
		t.Fatalf("New = %v, want development keys refused", b.err)
	}

	// Each file is checked: a provisioned keys.json beside a generated totp.key
	// still refuses.
	writeKey(t, dir, "keys.json", provisionedKeysJSON(t, false))
	b = bootKeys(t, productionIssuer, authkit.KeysConfig{Path: dir})
	if b.err == nil || !strings.Contains(b.err.Error(), "totp.key: development keys cannot sign") {
		t.Fatalf("New = %v, want the development totp.key refused", b.err)
	}

	used := mustBoot(t, bootKeys(t, "http://127.0.0.1:4780", authkit.KeysConfig{Path: dir}))
	if used.developmentLines() != 1 {
		t.Fatalf("development totp.key used without its INFO line:\n%s", used.logs)
	}
}

func TestVerifyOnlyGeneratesNothing(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	for _, issuer := range []string{localIssuer, productionIssuer} {
		dir := t.TempDir()
		b := mustBoot(t, bootKeys(t, issuer, authkit.KeysConfig{Path: dir, VerifyOnly: true}))
		if entries, _ := os.ReadDir(dir); len(entries) != 0 || b.developmentLines() != 0 {
			t.Fatalf("%s: VerifyOnly generated keys", issuer)
		}
		mustBoot(t, bootKeys(t, issuer, authkit.KeysConfig{VerifyOnly: true}))
	}
	if entries, _ := os.ReadDir(state); len(entries) != 0 {
		t.Fatal("VerifyOnly created a development directory")
	}
}

func noErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
