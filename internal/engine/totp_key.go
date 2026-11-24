package engine

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/keyfile"
)

// TOTP secret-encryption key as first-class vault key material (#148). The key
// lives next to the JWT signing keys: <Keys.Path>/totp.key. New resolves the
// persistent development path first; production defaults to /vault/auth.
// The file holds the AES key encoded as base64 or hex (raw bytes also
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
func resolveTOTPSecretKey(cfg config.Config, log *slog.Logger) ([]byte, error) {
	if len(cfg.TwoFactor.TOTPSecretKey) > 0 {
		if !validTOTPKeyLen(len(cfg.TwoFactor.TOTPSecretKey)) {
			return nil, fmt.Errorf("authkit: TwoFactor.TOTPSecretKey must be 16, 24, or 32 bytes, got %d", len(cfg.TwoFactor.TOTPSecretKey))
		}
		return append([]byte(nil), cfg.TwoFactor.TOTPSecretKey...), nil
	}
	if cfg.Keys.AllowEphemeralDevKeys && strings.TrimSpace(cfg.Keys.Path) == "" {
		return nil, fmt.Errorf("authkit: development key directory must be resolved for the issuer")
	}
	key, err := loadTOTPKey(log, totpKeysDir(cfg))
	if key == nil && err == nil && cfg.Keys.AllowEphemeralDevKeys {
		return ephemeralTOTPKey(log, totpKeysDir(cfg))
	}
	return key, err
}

// ephemeralTOTPKey retains its historical name, but development keys are now
// always persisted so restarts keep authenticator enrollments.
func ephemeralTOTPKey(log *slog.Logger, dir string) ([]byte, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("authkit: development TOTP key directory is required")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, totpKeyFilename)
	if err := createDevelopmentKey(path, []byte(base64.StdEncoding.EncodeToString(key))); err != nil {
		return nil, fmt.Errorf("authkit: persist dev TOTP key %s: %w", path, err)
	}
	return loadTOTPKey(log, dir)
}

// loadTOTPKey reads dir's totp.key; a missing one is (nil, nil).
func loadTOTPKey(log *slog.Logger, dir string) ([]byte, error) {
	path := filepath.Join(dir, totpKeyFilename)
	raw, err := keyfile.Read(log, dir, totpKeyFilename)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("authkit: TOTP key: %w", err)
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
