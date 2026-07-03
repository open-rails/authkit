package authcore

// #231/#232 construction-level tests: fail-closed key resolution (ephemeral
// dev keys are an explicit opt-in, never inferred from env or Environment),
// the single dev/prod classifier, and the <Keys.Path>/totp.key wiring.

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	jwtkit "github.com/open-rails/authkit/jwt"
)

func minimalKeysTestConfig() Config {
	return Config{
		Token: TokenConfig{
			Issuer:            "https://keys-test.example",
			IssuedAudiences:   []string{"app"},
			ExpectedAudiences: []string{"app"},
		},
	}
}

func TestNewFromConfigFailsClosedWithoutKeysOrOptIn(t *testing.T) {
	cfg := minimalKeysTestConfig()
	cfg.Keys = KeysConfig{Path: t.TempDir()} // no keys.json, no opt-in
	// Even a "dev" Environment must NOT unlock key generation (#231): the
	// classifier and the ephemeral-keys opt-in are deliberately independent.
	cfg.Environment = "dev"

	if _, err := NewFromConfig(cfg, nil); err == nil {
		t.Fatal("expected hard error with no keys and no AllowEphemeralDevKeys opt-in")
	}
}

func TestNewFromConfigEphemeralDevKeysOptIn(t *testing.T) {
	t.Chdir(t.TempDir()) // generated keys persist under .runtime/authkit relative to CWD

	cfg := minimalKeysTestConfig()
	cfg.Keys = KeysConfig{Path: t.TempDir(), AllowEphemeralDevKeys: true}

	svc, err := NewFromConfig(cfg, nil)
	if err != nil {
		t.Fatalf("explicit opt-in should generate dev keys: %v", err)
	}
	if len(svc.PublicKeysByKID()) == 0 {
		t.Fatal("expected a generated signing key in the keyset")
	}
}

func TestNewFromConfigLoadsKeysJSON(t *testing.T) {
	dir := t.TempDir()
	signer, err := jwtkit.NewRSASigner(2048, "cfg-kid")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(signer.PrivateKey()),
	})
	envelope, _ := json.Marshal(map[string]any{
		"active_key_id":          "cfg-kid",
		"active_private_key_pem": string(pemBytes),
	})
	if err := os.WriteFile(filepath.Join(dir, "keys.json"), envelope, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := minimalKeysTestConfig()
	cfg.Keys = KeysConfig{Path: dir} // no opt-in needed: real keys exist

	svc, err := NewFromConfig(cfg, nil)
	if err != nil {
		t.Fatalf("keys.json resolution: %v", err)
	}
	if _, ok := svc.PublicKeysByKID()["cfg-kid"]; !ok {
		t.Fatalf("expected cfg-kid in keyset, have %v", svc.PublicKeysByKID())
	}
}

func TestIsDevEnvironmentSingleClassifier(t *testing.T) {
	dev := []string{"", "dev", "Development", "local", "TEST", "  dev  "}
	for _, e := range dev {
		if !IsDevEnvironment(e) {
			t.Errorf("IsDevEnvironment(%q) = false, want true", e)
		}
	}
	// Everything else — including staging and unknown values — is prod-like.
	prodLike := []string{"prod", "production", "staging", "stage", "qa", "preprod", "banana"}
	for _, e := range prodLike {
		if IsDevEnvironment(e) {
			t.Errorf("IsDevEnvironment(%q) = true, want false (fail-closed)", e)
		}
	}
}

// #232: NewFromConfig loads <Keys.Path>/totp.key when no explicit override is
// set, so standalone/file-key deployments can actually enable TOTP.
func TestNewFromConfigWiresTOTPFileKey(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
	}
	if err := os.WriteFile(filepath.Join(dir, totpKeyFilename), []byte(hex.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := minimalKeysTestConfig()
	cfg.Keys = KeysConfig{Path: dir, VerifyOnly: true} // no keys.json needed

	svc, err := NewFromConfig(cfg, nil)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	got := svc.Config().TwoFactor.TOTPSecretKey
	if len(got) != 32 {
		t.Fatalf("TOTPSecretKey len = %d, want 32 (file key not wired)", len(got))
	}
	for i := range key {
		if got[i] != key[i] {
			t.Fatalf("TOTPSecretKey[%d] = %d, want %d", i, got[i], key[i])
		}
	}

	// The explicit override still wins over the file.
	override := make([]byte, 16)
	cfg.TwoFactor.TOTPSecretKey = override
	svc, err = NewFromConfig(cfg, nil)
	if err != nil {
		t.Fatalf("construct with override: %v", err)
	}
	if len(svc.Config().TwoFactor.TOTPSecretKey) != 16 {
		t.Fatalf("override should win; len = %d", len(svc.Config().TwoFactor.TOTPSecretKey))
	}

	// An invalid-length override is a hard construction error.
	cfg.TwoFactor.TOTPSecretKey = make([]byte, 20)
	if _, err := NewFromConfig(cfg, nil); err == nil {
		t.Fatal("20-byte TOTP override must fail construction")
	}
}
