package engine

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/open-rails/authkit/keys"
)

// defaultKeysPath is where External Secrets mounts keys.json by default.
const defaultKeysPath = "/vault/auth"

// signingKeys serves <dir>/keys.json through a hot-reloading keys.Watch
// source. A loopback issuer without one generates a development key first.
func signingKeys(dev *developmentKeys, log *slog.Logger) (*keys.FileSource, error) {
	path := filepath.Join(dev.dir, "keys.json")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if !dev.local {
			return nil, fmt.Errorf("authkit: no JWT signing keys: %s not found; mount keys.json or provide Deps.KeySource", path)
		}
		data, err := developmentKeysJSON()
		if err != nil {
			return nil, err
		}
		if err := dev.generate("keys.json", data); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("authkit: read signing key directory %s: %w", dev.dir, err)
	}
	if dev.local {
		if err := generateTOTPKey(dev); err != nil {
			return nil, err
		}
	}
	src, err := keys.Watch(dev.dir, log)
	if err != nil {
		return nil, fmt.Errorf("authkit: load JWT signing keys from %s: %w", dev.dir, err)
	}
	if err := dev.admit("keys.json or totp.key", src.Development()); err != nil {
		src.Close()
		return nil, err
	}
	return src, nil
}

func developmentKeysJSON() ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("authkit: generate development signing key: %w", err)
	}
	return json.Marshal(map[string]any{
		"development":            true,
		"active_key_id":          fmt.Sprintf("dev-%d", time.Now().Unix()),
		"active_private_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		"public_keys":            map[string]string{},
	})
}
