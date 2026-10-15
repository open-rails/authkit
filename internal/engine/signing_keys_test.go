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

// The constructor must bind development storage to its issuer first.
func TestResolveKeySourceRequiresResolvedDevelopmentPath(t *testing.T) {
	_, err := resolveKeySource("", true)
	require.ErrorContains(t, err, "resolved for the issuer")
}
