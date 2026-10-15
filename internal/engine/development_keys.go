package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-rails/authkit/internal/config"
)

// Resolve the development directory once for both signing and TOTP keys.
// Different issuers never accidentally share automatically generated keys.
func resolveDevelopmentKeys(c config.KeysConfig, issuer string) (config.KeysConfig, error) {
	c.Path = strings.TrimSpace(c.Path)
	if c.Path != "" || !c.AllowEphemeralDevKeys {
		return c, nil
	}
	if strings.TrimSpace(issuer) == "" {
		return c, errors.New("authkit: development keys require a token issuer")
	}
	state := os.Getenv("XDG_STATE_HOME")
	if state != "" && !filepath.IsAbs(state) {
		return c, errors.New("authkit: XDG_STATE_HOME must be an absolute path")
	}
	if state == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return c, fmt.Errorf("authkit: find development key home: %w", err)
		}
		state = filepath.Join(home, ".local", "state")
	}
	id := sha256.Sum256([]byte(issuer))
	c.Path = filepath.Join(state, "authkit", "development", hex.EncodeToString(id[:]))
	return c, nil
}

// Publish a complete private file without replacing another process's key.
// Linking only after write/sync/close avoids exposing a partially written
// O_EXCL file to concurrent starters, and leaves no stale lock after a crash.
func createDevelopmentKey(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".authkit-key-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = os.Link(f.Name(), path); errors.Is(err, os.ErrExist) {
		return nil // the winner has already published its complete file
	}
	return err
}
