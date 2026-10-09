package engine

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	stdlog "log"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-rails/authkit/internal/config"
)

// TOTP secret-encryption key as first-class vault key material (#148). The key
// lives next to the JWT signing keys: <Keys.Path>/totp.key (empty Keys.Path
// defaults to /vault/auth — identical resolution to keys.json; no env fallback,
// #231). The file holds the AES key encoded as base64 or hex (raw bytes also
// accepted), decoding to exactly 16, 24, or 32 bytes (AES-128/192/256). Hosts do
// not load or pass the secret manually on the normal path; the explicit
// TwoFactorConfig.TOTPSecretKey []byte is an override for tests/custom key
// management and wins over the file (#232).
const totpKeyFilename = "totp.key"

func validTOTPKeyLen(n int) bool { return n == 16 || n == 24 || n == 32 }

// resolveTOTPSecretKey returns the TOTP encryption key. The explicit override
// wins (validated). Otherwise it loads <Keys.Path>/totp.key, generated first
// under Keys.AllowEphemeralDevKeys. Without either it returns (nil, nil):
// TOTP is then unavailable, which New refuses when no other second factor can
// be enrolled. Invalid material (wrong length, bad encoding, unsafe
// permissions) is a hard construction error, the same rigor as JWT signing
// keys.
func resolveTOTPSecretKey(cfg config.Config) ([]byte, error) {
	if len(cfg.TwoFactor.TOTPSecretKey) > 0 {
		if !validTOTPKeyLen(len(cfg.TwoFactor.TOTPSecretKey)) {
			return nil, fmt.Errorf("authkit: TwoFactor.TOTPSecretKey must be 16, 24, or 32 bytes, got %d", len(cfg.TwoFactor.TOTPSecretKey))
		}
		return append([]byte(nil), cfg.TwoFactor.TOTPSecretKey...), nil
	}
	key, err := loadTOTPKey(filepath.Join(totpKeysDir(cfg), totpKeyFilename))
	if key == nil && err == nil && cfg.Keys.AllowEphemeralDevKeys {
		return ephemeralTOTPKey(cfg.Keys.Path)
	}
	return key, err
}

// ephemeralTOTPKey generates the TOTP key of a development deployment: in
// memory, or written to <dir>/totp.key when Keys.Path is set, so restarts keep
// authenticator enrollments.
func ephemeralTOTPKey(dir string) ([]byte, error) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	if dir = strings.TrimSpace(dir); dir == "" {
		return key, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("authkit: persist dev TOTP key under %s: %w", dir, err)
	}
	path := filepath.Join(dir, totpKeyFilename)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return loadTOTPKey(path) // another replica wrote it first
	}
	if err == nil {
		_, err = f.WriteString(base64.StdEncoding.EncodeToString(key))
		err = errors.Join(err, f.Close())
	}
	if err != nil {
		return nil, fmt.Errorf("authkit: persist dev TOTP key %s: %w", path, err)
	}
	return key, nil
}

// loadTOTPKey reads a totp.key file; a missing one is (nil, nil).
func loadTOTPKey(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("authkit: stat TOTP key %s: %w", path, err)
	}
	// Group-read is allowed: a Kubernetes secret volume with fsGroup mounts it
	// 0440, the only way a non-root pod reads it.
	mode := info.Mode().Perm()
	if mode&0o022 != 0 {
		return nil, fmt.Errorf("authkit: TOTP key %s is group/world-writable (%#o) — refuse to load (expected 0600, 0400 or 0440)", path, mode)
	}
	if mode&0o004 != 0 {
		stdlog.Printf("authkit: warning: TOTP key %s is world-readable (%#o); expected 0600, 0400 or 0440", path, mode)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("authkit: read TOTP key %s: %w", path, err)
	}
	key, err := decodeTOTPKeyBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("authkit: TOTP key %s: %w", path, err)
	}
	return key, nil
}

func totpKeysDir(cfg config.Config) string {
	if p := strings.TrimSpace(cfg.Keys.Path); p != "" {
		return p
	}
	return defaultKeysPath
}

// decodeTOTPKeyBytes accepts the key as base64 (std/url, padded or not), hex, or
// raw bytes — whichever decodes to a valid AES key length.
func decodeTOTPKeyBytes(raw []byte) ([]byte, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return nil, fmt.Errorf("file is empty")
	}
	if b, err := hex.DecodeString(s); err == nil && validTOTPKeyLen(len(b)) {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && validTOTPKeyLen(len(b)) {
			return b, nil
		}
	}
	if validTOTPKeyLen(len(s)) {
		return []byte(s), nil
	}
	return nil, fmt.Errorf("must decode to 16, 24, or 32 bytes (base64, hex, or raw)")
}
