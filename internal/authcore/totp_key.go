package authcore

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	stdlog "log"
	"os"
	"path/filepath"
	"strings"

	jwtkit "github.com/open-rails/authkit/jwt"
)

// TOTP secret-encryption key as first-class vault key material (#148). The key
// lives next to the JWT signing keys: <Keys.Path>/totp.key (empty Keys.Path
// defaults to /vault/auth — identical resolution to keys.json; no env fallback,
// #231). The file holds the AES key encoded as base64 or hex (raw bytes also
// accepted), decoding to exactly 16, 24, or 32 bytes (AES-128/192/256). Hosts do
// not load or pass the secret manually on the normal embedded path; the explicit
// TwoFactorConfig.TOTPSecretKey []byte is an override for tests/custom key
// management and wins over the file. Wired into NewFromConfig (#232).
const totpKeyFilename = "totp.key"

func validTOTPKeyLen(n int) bool { return n == 16 || n == 24 || n == 32 }

// resolveTOTPSecretKey returns the TOTP encryption key. The explicit override
// wins (validated). Otherwise it loads <Keys.Path>/totp.key. A missing file
// returns (nil, nil) — TOTP enrollment then fails closed at use. Invalid material
// (wrong length, bad encoding, unsafe permissions) is a hard construction error,
// the same rigor as JWT signing keys.
func resolveTOTPSecretKey(cfg Config) ([]byte, error) {
	if len(cfg.TwoFactor.TOTPSecretKey) > 0 {
		if !validTOTPKeyLen(len(cfg.TwoFactor.TOTPSecretKey)) {
			return nil, fmt.Errorf("authkit: TwoFactor.TOTPSecretKey must be 16, 24, or 32 bytes, got %d", len(cfg.TwoFactor.TOTPSecretKey))
		}
		return append([]byte(nil), cfg.TwoFactor.TOTPSecretKey...), nil
	}
	path := filepath.Join(totpKeysDir(cfg), totpKeyFilename)
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, nil // no key configured — TOTP fails closed at enrollment.
	}
	if err != nil {
		return nil, fmt.Errorf("authkit: stat TOTP key %s: %w", path, err)
	}
	mode := info.Mode().Perm()
	if mode&0o022 != 0 {
		return nil, fmt.Errorf("authkit: TOTP key %s is group/world-writable (%#o) — refuse to load (expected 0600/0400)", path, mode)
	}
	if mode&0o044 != 0 {
		stdlog.Printf("authkit: warning: TOTP key %s is group/world-readable (%#o); expected 0600/0400", path, mode)
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

// twoFactorMethodListed mirrors twoFactorMethodConfigured for construction-time
// checks: empty Methods means all three are offered.
func twoFactorMethodListed(methods []TwoFactorMethod, m TwoFactorMethod) bool {
	if len(methods) == 0 {
		return true
	}
	for _, x := range methods {
		if x == m {
			return true
		}
	}
	return false
}

func totpKeysDir(cfg Config) string {
	if p := strings.TrimSpace(cfg.Keys.Path); p != "" {
		return p
	}
	return jwtkit.DefaultAuthKeysPath
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

// normalizeTwoFactorMode defaults an empty mode to Optional and rejects nothing
// else (unknown strings are treated as Optional for forward tolerance, but the
// three canonical values are the contract).
func normalizeTwoFactorMode(m TwoFactorMode) TwoFactorMode {
	switch m {
	case TwoFactorDisabled, TwoFactorOptional, TwoFactorRequired:
		return m
	default:
		return TwoFactorOptional
	}
}
