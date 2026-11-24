// Package keyfile reads key material from a key directory (Keys.Path): the
// signing keys' keys.json and the TOTP key. A file another account can
// rewrite is refused, so only its owner can swap the keys.
package keyfile

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Read reads the file name (one path segment) under dir. A group- or
// world-writable file is refused; a world-readable one is read and logged on
// log.
// Group-read is allowed: a Kubernetes secret volume with fsGroup mounts its
// files 0440, the only way a non-root pod reads them. A missing file is an
// error satisfying errors.Is(err, fs.ErrNotExist).
func Read(log *slog.Logger, dir, name string) ([]byte, error) {
	if clean := filepath.Clean(name); clean != name || name == "." || name == ".." || strings.ContainsRune(name, os.PathSeparator) {
		return nil, fmt.Errorf("invalid key file name %q", name)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name)
	mode := info.Mode().Perm()
	if mode&0o022 != 0 {
		return nil, fmt.Errorf("%s is group/world-writable (%#o): refusing to load it (expected 0600, 0400 or 0440)", path, mode)
	}
	if mode&0o004 != 0 {
		log.Warn("authkit: key file is world-readable; expected 0600, 0400 or 0440", "path", path, "mode", fmt.Sprintf("%#o", mode))
	}
	return io.ReadAll(f)
}
