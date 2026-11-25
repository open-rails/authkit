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
// lives next to the JWT signing keys: <Keys.Path>/totp.key, base64 or hex
// (raw bytes also accepted), decoding to exactly 16, 24, or 32 bytes
// (AES-128/192/256). A key AuthKit generated for a loopback issuer is
// prefixed "development:". TwoFactorConfig.TOTPSecretKey overrides the file
// (#232).
const totpKeyFilename = "totp.key"

// developmentTOTPPrefix marks a generated totp.key as a development key.
const developmentTOTPPrefix = "development:"

func validTOTPKeyLen(n int) bool { return n == 16 || n == 24 || n == 32 }

// resolveTOTPSecretKey returns the TOTP encryption key: the explicit override,
// else <dir>/totp.key, which a signing engine with a loopback issuer
// generates when missing. Without either it returns (nil, nil): TOTP is then
// unavailable, which New refuses when no other second factor can be
// enrolled. Invalid material (wrong length, bad encoding, unsafe permissions)
// is a hard construction error, the same rigor as JWT signing keys.
func resolveTOTPSecretKey(cfg config.Config, signs bool, dev *developmentKeys, log *slog.Logger) ([]byte, error) {
	if len(cfg.TwoFactor.TOTPSecretKey) > 0 {
		if !validTOTPKeyLen(len(cfg.TwoFactor.TOTPSecretKey)) {
			return nil, fmt.Errorf("authkit: TwoFactor.TOTPSecretKey must be 16, 24, or 32 bytes, got %d", len(cfg.TwoFactor.TOTPSecretKey))
		}
		return append([]byte(nil), cfg.TwoFactor.TOTPSecretKey...), nil
	}
	key, development, err := loadTOTPKey(log, dev.dir)
	if err == nil && key == nil && signs && dev.local {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		if err := dev.generate(totpKeyFilename, []byte(developmentTOTPPrefix+base64.StdEncoding.EncodeToString(raw))); err != nil {
			return nil, err
		}
		key, development, err = loadTOTPKey(log, dev.dir)
	}
	if err != nil || key == nil {
		return nil, err
	}
	if err := dev.admit(totpKeyFilename, development); err != nil {
		return nil, err
	}
	return key, nil
}

// loadTOTPKey reads dir's totp.key; a missing one is (nil, false, nil).
func loadTOTPKey(log *slog.Logger, dir string) (key []byte, development bool, _ error) {
	path := filepath.Join(dir, totpKeyFilename)
	raw, err := keyfile.Read(log, dir, totpKeyFilename)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("authkit: TOTP key: %w", err)
	}
	s, development := strings.CutPrefix(strings.TrimSpace(string(raw)), developmentTOTPPrefix)
	key, err = decodeTOTPKeyBytes(s)
	if err != nil {
		return nil, false, fmt.Errorf("authkit: TOTP key %s: %w", path, err)
	}
	return key, development, nil
}

// decodeTOTPKeyBytes accepts the key as base64 (std/url, padded or not), hex, or
// raw bytes — whichever decodes to a valid AES key length.
func decodeTOTPKeyBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
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
