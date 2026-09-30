package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/keys"
	"github.com/stretchr/testify/require"
)

func TestClientOwnedResourceLifecycle(t *testing.T) {
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	data, err := json.Marshal(map[string]any{
		"active_key_id": "lifecycle",
		"active_private_key_pem": string(pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
		})),
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keys.json"), data, 0600))
	config := Config{
		Token:     TokenConfig{Issuer: "https://lifecycle.test", IssuedAudiences: []string{"test"}},
		Keys:      KeysConfig{Path: dir},
		TwoFactor: TwoFactorConfig{Mode: iam.TwoFactorDisabled},
	}

	// Labels are inherited by the real resource goroutines started inside Do.
	// This observes only this subtest's resources, never global goroutine counts.
	label := "authkit-client-lifecycle"
	resourceCount := func(t *testing.T) int {
		t.Helper()
		var profile bytes.Buffer
		require.NoError(t, pprof.Lookup("goroutine").WriteTo(&profile, 1))
		return strings.Count(profile.String(), `"`+label+`":"`+t.Name()+`"`)
	}
	awaitClosed := func(t *testing.T) {
		t.Helper()
		require.Eventually(t, func() bool { return resourceCount(t) == 0 }, time.Second, time.Millisecond,
			"client-owned background resources survived cleanup")
	}

	t.Run("close", func(t *testing.T) {
		var client *Engine
		pprof.Do(context.Background(), pprof.Labels(label, t.Name()), func(context.Context) {
			client, err = newEngine(config, Deps{})
		})
		require.NoError(t, err)
		t.Cleanup(client.Close)
		require.Eventually(t, func() bool { return resourceCount(t) == 1 }, time.Second, time.Millisecond)
		client.Close()
		client.Close()
		awaitClosed(t)
	})

	t.Run("config", func(t *testing.T) {
		cfg := config
		cfg.Schema = "invalid schema"
		pprof.Do(context.Background(), pprof.Labels(label, t.Name()), func(context.Context) {
			client, err := newEngine(cfg, Deps{})
			require.Error(t, err)
			require.Nil(t, client)
		})
		awaitClosed(t)
	})

	t.Run("borrowed", func(t *testing.T) {
		watched, err := keys.Watch(dir)
		require.NoError(t, err)
		t.Cleanup(watched.Close)
		cfg := config
		cfg.Keys.Source = watched
		client, err := newEngine(cfg, Deps{})
		require.NoError(t, err)
		client.Close()

		// A borrowed key source keeps reloading after Close.
		require.NoError(t, os.WriteFile(filepath.Join(dir, "keys.json"),
			bytes.ReplaceAll(data, []byte(`"lifecycle"`), []byte(`"rotated"`)), 0600))
		future := time.Now().Add(time.Second)
		require.NoError(t, os.Chtimes(filepath.Join(dir, "keys.json"), future, future))
		// keys.Watch polls every 10s.
		require.Eventually(t, func() bool { return watched.ActiveSigner().KID() == "rotated" }, 15*time.Second, 50*time.Millisecond)
	})
}
