package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/open-rails/authkit/keys"
	"github.com/stretchr/testify/require"
)

// Without keys.json and without the dev-key opt-in, resolution fails closed:
// it never generates a signing key on its own (#231).
func TestResolveKeySourceFailsClosedWithoutOptIn(t *testing.T) {
	_, err := resolveKeySource(filepath.Join(t.TempDir(), "empty"), false)
	require.Error(t, err)
}

// A dev key generated under an explicit path is persisted (0600) and reused.
func TestResolveKeySourcePersistsDevKeysUnderExplicitPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	first, err := resolveKeySource(dir, true)
	require.NoError(t, err)
	t.Cleanup(first.(*keys.FileSource).Close)
	fi, err := os.Stat(filepath.Join(dir, "keys.json"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	second, err := resolveKeySource(dir, true)
	require.NoError(t, err)
	t.Cleanup(second.(*keys.FileSource).Close)
	require.Equal(t, first.ActiveSigner().KID(), second.ActiveSigner().KID())
}

// Without a path a dev key stays in memory: nothing is written relative to
// the working directory.
func TestResolveKeySourceDevKeysStayInMemoryWithoutPath(t *testing.T) {
	if _, err := os.Stat(filepath.Join(defaultKeysPath, "keys.json")); err == nil {
		t.Skipf("%s/keys.json exists on this host; the file branch would win", defaultKeysPath)
	}
	cwd := t.TempDir()
	t.Chdir(cwd)
	ks, err := resolveKeySource("", true)
	require.NoError(t, err)
	require.IsType(t, keys.Static{}, ks)
	entries, err := os.ReadDir(cwd)
	require.NoError(t, err)
	require.Empty(t, entries)
}
