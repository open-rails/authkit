package engine

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/open-rails/authkit/keys"
)

// defaultKeysPath is where External Secrets mounts keys.json by default.
const defaultKeysPath = "/vault/auth"

// resolveKeySource resolves the signing keys when the host passes no source:
// <path>/keys.json (default /vault/auth), served through a hot-reloading
// keys.Watch source; else, with allowDevKeys only, atomically generates a
// persistent RSA key. New resolves the per-issuer development path first.
func resolveKeySource(path string, allowDevKeys bool) (keys.Source, error) {
	path = strings.TrimSpace(path)
	if path == "" && allowDevKeys {
		return nil, errors.New("development key directory must be resolved for the issuer")
	}
	dir := path
	if dir == "" {
		dir = defaultKeysPath
	}
	if _, err := os.Stat(filepath.Join(dir, "keys.json")); err == nil {
		src, err := keys.Watch(dir)
		if err != nil {
			return nil, fmt.Errorf("failed to load keys from %s: %w", dir, err)
		}
		return src, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read signing key directory %s: %w", dir, err)
	}
	if !allowDevKeys {
		return nil, fmt.Errorf("no JWT signing keys: %s/keys.json not found and ephemeral dev keys are not enabled; mount keys.json, provide an explicit KeySource, or opt in with AllowEphemeralDevKeys for local development", dir)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate development keys: %w", err)
	}
	kid := fmt.Sprintf("dev-%d", time.Now().Unix())
	data, err := json.Marshal(map[string]any{
		"active_key_id":          kid,
		"active_private_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		"public_keys":            map[string]string{},
	})
	if err != nil {
		return nil, err
	}
	if err := createDevelopmentKey(filepath.Join(path, "keys.json"), data); err != nil {
		return nil, fmt.Errorf("persist dev keys under %s: %w", path, err)
	}
	return keys.Watch(path)
}
