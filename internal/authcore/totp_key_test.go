package authcore

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestDecodeTOTPKeyBytes(t *testing.T) {
	key32 := make([]byte, 32)
	for i := range key32 {
		key32[i] = byte(i)
	}
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"hex32", hex.EncodeToString(key32), true},
		{"base64std32", base64.StdEncoding.EncodeToString(key32), true},
		{"base64raw32", base64.RawStdEncoding.EncodeToString(key32), true},
		{"raw16", "0123456789abcdef", true}, // 16 raw bytes
		{"whitespace", "  " + hex.EncodeToString(key32) + "\n", true},
		{"empty", "", false},
		{"badlen", hex.EncodeToString(make([]byte, 20)), false}, // 20 bytes is not a valid AES key
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := decodeTOTPKeyBytes([]byte(c.in))
			if c.ok && (err != nil || !validTOTPKeyLen(len(b))) {
				t.Fatalf("decode(%q) = %v, %v; want valid key", c.in, b, err)
			}
			if !c.ok && err == nil {
				t.Fatalf("decode(%q) expected error", c.in)
			}
		})
	}
}

func TestResolveTOTPSecretKey(t *testing.T) {
	// Override wins and must be a valid length.
	if _, err := resolveTOTPSecretKey(Config{TwoFactor: TwoFactorConfig{TOTPSecretKey: make([]byte, 32)}}); err != nil {
		t.Fatalf("valid 32-byte override: %v", err)
	}
	if _, err := resolveTOTPSecretKey(Config{TwoFactor: TwoFactorConfig{TOTPSecretKey: make([]byte, 20)}}); err == nil {
		t.Fatal("20-byte override should be rejected")
	}

	// File loading from <Keys.Path>/totp.key.
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := os.WriteFile(filepath.Join(dir, totpKeyFilename), []byte(hex.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveTOTPSecretKey(Config{Keys: KeysConfig{Path: dir}})
	if err != nil {
		t.Fatalf("load from file: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("loaded key len = %d, want 32", len(got))
	}

	// Missing file -> (nil, nil): TOTP fails closed later, not at construction.
	if k, err := resolveTOTPSecretKey(Config{Keys: KeysConfig{Path: t.TempDir()}}); err != nil || k != nil {
		t.Fatalf("missing key file = %v, %v; want nil, nil", k, err)
	}

	// Group/world-writable file is refused. WriteFile's perm is masked by the
	// umask (typically 022, which would strip the write bits and land at 0644), so
	// Chmod explicitly to actually make the file group/world-writable.
	bad := t.TempDir()
	p := filepath.Join(bad, totpKeyFilename)
	if err := os.WriteFile(p, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveTOTPSecretKey(Config{Keys: KeysConfig{Path: bad}}); err == nil {
		t.Fatal("world-writable key file should be refused")
	}
}

func TestTOTPSecretRoundTripVersioned(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 7)
	}
	s := NewService(Config{Token: TokenConfig{Issuer: "https://test"}, TwoFactor: TwoFactorConfig{TOTPSecretKey: key}}, Keyset{})

	const secret = "JBSWY3DPEHPK3PXP"
	enc, err := s.encryptTOTPSecret(secret)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if enc[0] != totpKeyVersion {
		t.Fatalf("expected version prefix %d, got %d", totpKeyVersion, enc[0])
	}
	got, err := s.decryptTOTPSecret(enc)
	if err != nil || got != secret {
		t.Fatalf("decrypt = %q, %v; want %q", got, err, secret)
	}

	// Tampering with the version byte is rejected (it is authenticated as AAD).
	enc[0] = 9
	if _, err := s.decryptTOTPSecret(enc); err == nil {
		t.Fatal("decrypt of wrong-version blob should fail")
	}
}

func TestTwoFactorMethodAvailable(t *testing.T) {
	key := make([]byte, 32)
	// Disabled blocks everything.
	disabled := NewService(Config{Token: TokenConfig{Issuer: "x"}, TwoFactor: TwoFactorConfig{TOTPSecretKey: key, Mode: TwoFactorDisabled}}, Keyset{})
	for _, m := range []string{"email", "sms", "totp"} {
		if disabled.TwoFactorMethodAvailable(m) {
			t.Fatalf("disabled: %s should be unavailable", m)
		}
	}
	if len(disabled.TwoFactorAllowedMethods()) != 0 {
		t.Fatal("disabled: no allowed methods")
	}

	// Optional, TOTP-only policy with a key: only TOTP is available (no email/SMS
	// sender wired).
	totpOnly := NewService(Config{Token: TokenConfig{Issuer: "x"}, TwoFactor: TwoFactorConfig{TOTPSecretKey: key, Mode: TwoFactorOptional, Methods: []TwoFactorMethod{TwoFactorTOTP}}}, Keyset{})
	if !totpOnly.TwoFactorMethodAvailable("totp") {
		t.Fatal("totp should be available with a key and totp in policy")
	}
	if totpOnly.TwoFactorMethodAvailable("email") || totpOnly.TwoFactorMethodAvailable("sms") {
		t.Fatal("email/sms not in policy -> unavailable")
	}

	// TOTP without a key fails closed even when enabled by policy.
	noKey := NewService(Config{Token: TokenConfig{Issuer: "x"}, TwoFactor: TwoFactorConfig{Mode: TwoFactorOptional}}, Keyset{})
	if noKey.TwoFactorMethodAvailable("totp") {
		t.Fatal("totp without a key must be unavailable (fail closed)")
	}
}
