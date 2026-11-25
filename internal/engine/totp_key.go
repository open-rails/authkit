package engine

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/open-rails/authkit/keys"
)

// totpKeyFilename is the TOTP secret-encryption key beside keys.json (#148),
// which keys.Watch serves (keys.TOTPSource).
const totpKeyFilename = "totp.key"

// generateTOTPKey writes a development totp.key into a loopback issuer's key
// directory when it has none.
func generateTOTPKey(dev *developmentKeys) error {
	if _, err := os.Stat(filepath.Join(dev.dir, totpKeyFilename)); !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	return dev.generate(totpKeyFilename, []byte("development:"+base64.StdEncoding.EncodeToString(raw)))
}

// totpKeyOf is src's TOTP key (keys.TOTPSource); nil when it holds none, and
// TOTP is then unavailable.
func totpKeyOf(src keys.Source) ([]byte, error) {
	t, ok := src.(keys.TOTPSource)
	if !ok {
		return nil, nil
	}
	key := t.TOTPKey()
	if n := len(key); n != 0 && n != 16 && n != 24 && n != 32 {
		return nil, fmt.Errorf("authkit: Deps.KeySource's TOTP key must be 16, 24, or 32 bytes, got %d", n)
	}
	return append([]byte(nil), key...), nil
}
