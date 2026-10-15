package engine

import (
	"bytes"
	"context"
	"crypto/rsa"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/keys"
	"github.com/stretchr/testify/require"
)

func TestDevelopmentKeysPersistAcrossEngineRestarts(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	cfg := config.Config{Keys: config.KeysConfig{AllowEphemeralDevKeys: true}, Token: config.TokenConfig{Issuer: "https://development.example", IssuedAudiences: []string{"development"}}}
	first, err := New(t.Context(), cfg, config.Deps{})
	require.NoError(t, err)
	dir := first.Config().Keys.Path
	require.DirExists(t, dir)
	require.Equal(t, filepath.Join(state, "authkit", "development"), filepath.Dir(dir))
	public := first.keys.ActiveSigner().Public().(*rsa.PublicKey)
	secret := bytes.Clone(first.Config().TwoFactor.TOTPSecretKey)
	require.Len(t, secret, 32)
	require.NoError(t, first.Close(context.Background()))
	second, err := New(t.Context(), cfg, config.Deps{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = second.Close(context.Background()) })
	require.Equal(t, dir, second.Config().Keys.Path)
	require.Zero(t, public.N.Cmp(second.keys.ActiveSigner().Public().(*rsa.PublicKey).N))
	require.Equal(t, secret, second.Config().TwoFactor.TOTPSecretKey)
	for _, name := range []string{"keys.json", "totp.key"} {
		info, err := os.Stat(filepath.Join(dir, name))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func TestDevelopmentKeysExplicitPath(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	dir := filepath.Join(t.TempDir(), "shared")
	cfg := config.Config{Keys: config.KeysConfig{Path: dir, AllowEphemeralDevKeys: true}, Token: config.TokenConfig{Issuer: "https://explicit.example", IssuedAudiences: []string{"development"}}}
	e, err := New(t.Context(), cfg, config.Deps{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close(context.Background()) })
	require.Equal(t, dir, e.Config().Keys.Path)
	for _, name := range []string{"keys.json", "totp.key"} {
		require.FileExists(t, filepath.Join(dir, name))
	}
	entries, err := os.ReadDir(state)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestDevelopmentKeysDirectorySelection(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	dev := config.KeysConfig{AllowEphemeralDevKeys: true}
	first, err := resolveDevelopmentKeys(dev, "https://a.example/path")
	require.NoError(t, err)
	again, err := resolveDevelopmentKeys(dev, "https://a.example/path")
	require.NoError(t, err)
	other, err := resolveDevelopmentKeys(dev, "https://b.example/path")
	require.NoError(t, err)
	require.Equal(t, first.Path, again.Path)
	require.NotEqual(t, first.Path, other.Path)
	explicit := filepath.Join(t.TempDir(), "shared")
	chosen, err := resolveDevelopmentKeys(config.KeysConfig{Path: explicit, AllowEphemeralDevKeys: true}, "https://a.example")
	require.NoError(t, err)
	require.Equal(t, explicit, chosen.Path)
	t.Setenv("XDG_STATE_HOME", "relative-state")
	_, err = resolveDevelopmentKeys(dev, "https://a.example")
	require.ErrorContains(t, err, "absolute")
	_, err = resolveDevelopmentKeys(config.KeysConfig{Path: explicit, AllowEphemeralDevKeys: true}, "https://a.example")
	require.NoError(t, err, "explicit paths must not depend on XDG")
	t.Setenv("XDG_STATE_HOME", "")
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	fallback, err := resolveDevelopmentKeys(dev, "https://a.example")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(home, ".local", "state", "authkit", "development"), filepath.Dir(fallback.Path))
}

func TestDevelopmentKeysConcurrentCreation(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	c, err := resolveDevelopmentKeys(config.KeysConfig{AllowEphemeralDevKeys: true}, "https://concurrent.example")
	require.NoError(t, err)
	const count = 6
	sources := make([]keys.Source, count)
	secrets := make([][]byte, count)
	errors := make([]error, count)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range count {
		wg.Go(func() {
			<-start
			sources[i], errors[i] = resolveKeySource(c.Path, true)
			if errors[i] == nil {
				secrets[i], errors[i] = resolveTOTPSecretKey(config.Config{Keys: c})
			}
		})
	}
	close(start)
	wg.Wait()
	for i := range count {
		require.NoError(t, errors[i])
		t.Cleanup(sources[i].(*keys.FileSource).Close)
		require.Zero(t, sources[0].ActiveSigner().Public().(*rsa.PublicKey).N.Cmp(sources[i].ActiveSigner().Public().(*rsa.PublicKey).N))
		require.Equal(t, secrets[0], secrets[i])
	}
	entries, err := os.ReadDir(c.Path)
	require.NoError(t, err)
	require.Len(t, entries, 2, "temporary files must be removed")
}

func TestProductionMissingKeysNeverWrites(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	dir := filepath.Join(state, "missing-production-keys")
	cfg := config.Config{Keys: config.KeysConfig{Path: dir}, Token: config.TokenConfig{Issuer: "https://production.example", IssuedAudiences: []string{"production"}}}
	engine, err := New(t.Context(), cfg, config.Deps{})
	require.ErrorContains(t, err, "no JWT signing keys")
	require.Nil(t, engine)
	entries, err := os.ReadDir(state)
	require.NoError(t, err)
	require.Empty(t, entries)
	unchanged, err := resolveDevelopmentKeys(config.KeysConfig{}, cfg.Token.Issuer)
	require.NoError(t, err)
	require.Empty(t, unchanged.Path)
}
