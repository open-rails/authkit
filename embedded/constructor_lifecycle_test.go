package embedded

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	memorystore "github.com/open-rails/authkit/internal/storage/memory"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/stretchr/testify/require"
)

func TestClientOwnedResourceLifecycle(t *testing.T) {
	dir := t.TempDir()
	signer, err := jwtkit.NewRSASigner(2048, "lifecycle")
	require.NoError(t, err)
	data, err := json.Marshal(map[string]any{
		"active_key_id": "lifecycle",
		"active_private_key_pem": string(pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(signer.PrivateKey()),
		})),
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keys.json"), data, 0600))
	config := Config{
		Token:     TokenConfig{Issuer: "https://lifecycle.test", IssuedAudiences: []string{"test"}},
		Keys:      KeysConfig{Path: dir},
		Ephemeral: EphemeralConfig{AllowMemory: true},
		TwoFactor: TwoFactorConfig{Mode: TwoFactorDisabled},
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
		var client *Client
		pprof.Do(context.Background(), pprof.Labels(label, t.Name()), func(context.Context) {
			client, err = New(config, Deps{})
		})
		require.NoError(t, err)
		t.Cleanup(client.Close)
		require.Eventually(t, func() bool { return resourceCount(t) == 2 }, time.Second, time.Millisecond)
		client.Close()
		client.Close()
		awaitClosed(t)
	})

	for _, failure := range []string{"config", "backend"} {
		t.Run(failure, func(t *testing.T) {
			cfg := config
			if failure == "config" {
				cfg.Schema = "invalid schema"
			} else {
				cfg.Ephemeral.AllowMemory = false
			}
			pprof.Do(context.Background(), pprof.Labels(label, t.Name()), func(context.Context) {
				client, err := New(cfg, Deps{})
				require.Error(t, err)
				require.Nil(t, client)
			})
			awaitClosed(t)
		})
	}

	t.Run("borrowed", func(t *testing.T) {
		store := memorystore.NewKV(memorystore.WithSweepInterval(time.Millisecond))
		t.Cleanup(store.Close)
		keys, err := jwtkit.NewFileKeySource(dir, time.Millisecond, nil)
		require.NoError(t, err)
		t.Cleanup(keys.Close)
		cfg := config
		cfg.Keys.Source = keys
		client, err := New(cfg, Deps{EphemeralStore: store})
		require.NoError(t, err)
		client.Close()
		cfg.Ephemeral.AllowMemory = false
		client, err = New(cfg, Deps{EphemeralStore: store})
		require.Error(t, err)
		require.Nil(t, client)

		// Exercise background work after both Close and failed construction.
		// Get would expire a value on access even if its sweeper had stopped.
		require.NoError(t, store.Set(context.Background(), "expires", []byte("value"), time.Millisecond))
		require.Eventually(t, func() bool { return store.Len() == 0 }, time.Second, time.Millisecond)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "keys.json"),
			bytes.ReplaceAll(data, []byte(`"lifecycle"`), []byte(`"rotated"`)), 0600))
		future := time.Now().Add(time.Second)
		require.NoError(t, os.Chtimes(filepath.Join(dir, "keys.json"), future, future))
		require.Eventually(t, func() bool { return keys.ActiveSigner().KID() == "rotated" }, time.Second, time.Millisecond)
	})
}
