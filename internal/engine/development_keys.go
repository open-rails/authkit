package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-rails/authkit/internal/config"
)

// developmentKeys is the key directory and its policy for one issuer. A
// loopback issuer is a local deployment: AuthKit generates the keys it lacks,
// marked as development keys. Any other issuer never generates and refuses
// marked keys, so a directory first used locally never signs for a real one.
type developmentKeys struct {
	issuer    string
	dir       string
	local     bool
	generated []string
	used      bool
}

// newDevelopmentKeys resolves the key directory: Keys.Path; else for a
// loopback issuer its own local state directory, so issuers never share
// generated keys; else /vault/auth.
func newDevelopmentKeys(c config.KeysConfig, issuer string) (*developmentKeys, error) {
	d := &developmentKeys{issuer: issuer, dir: strings.TrimSpace(c.Path), local: config.LoopbackURL(issuer)}
	switch {
	case d.dir != "":
		return d, nil
	case !d.local:
		d.dir = defaultKeysPath
		return d, nil
	}
	state := os.Getenv("XDG_STATE_HOME")
	if state != "" && !filepath.IsAbs(state) {
		return nil, errors.New("authkit: XDG_STATE_HOME must be an absolute path")
	}
	if state == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("authkit: find development key home: %w", err)
		}
		state = filepath.Join(home, ".local", "state")
	}
	id := sha256.Sum256([]byte(issuer))
	d.dir = filepath.Join(state, "authkit", "development", hex.EncodeToString(id[:]))
	return d, nil
}

// admit refuses development keys in the key directory's file unless the
// issuer is loopback.
func (d *developmentKeys) admit(file string, development bool) error {
	if !development {
		return nil
	}
	if err := d.refuse(filepath.Join(d.dir, file)); err != nil {
		return err
	}
	d.used = true
	return nil
}

// refuse is the refusal of development keys found at where, nil for a
// loopback issuer.
func (d *developmentKeys) refuse(where string) error {
	if d.local {
		return nil
	}
	return fmt.Errorf("authkit: %s: development keys cannot sign for %s: provision real keys", where, d.issuer)
}

// generate publishes data as the key directory's file name, unless another
// starter already did.
func (d *developmentKeys) generate(name string, data []byte) error {
	created, err := createDevelopmentKey(filepath.Join(d.dir, name), data)
	if err != nil {
		return fmt.Errorf("authkit: persist development %s under %s: %w", name, d.dir, err)
	}
	if created {
		d.generated = append(d.generated, name)
	}
	return nil
}

func (d *developmentKeys) report(log *slog.Logger) {
	if d.used {
		log.Info("authkit: signing with development keys, generated for a loopback issuer", "dir", d.dir, "generated", d.generated)
	}
}

// Publish a complete private file without replacing another process's key.
// Linking only after write/sync/close avoids exposing a partially written
// O_EXCL file to concurrent starters, and leaves no stale lock after a crash.
// created is false when another starter published first.
func createDevelopmentKey(path string, data []byte) (created bool, _ error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".authkit-key-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return false, err
	}
	if err = os.Link(f.Name(), path); errors.Is(err, os.ErrExist) {
		return false, nil
	}
	return err == nil, err
}
