package critical_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/keys"
	riverkit "github.com/open-rails/helpers/river"
	"github.com/riverqueue/river"
)

// writeKeyFile writes a key file and gives it mode, whatever the umask.
func writeKeyFile(t *testing.T, dir, name string, data []byte, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(dir, name)
	noError(t, os.WriteFile(path, data, 0o600))
	noError(t, os.Chmod(path, mode))
}

// keysJSON is a keys.json whose active key is a fresh RSA key named kid.
func keysJSON(t *testing.T, kid string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	noError(t, err)
	data, err := json.Marshal(map[string]any{
		"active_key_id":          kid,
		"active_private_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		"public_keys":            map[string]string{},
	})
	noError(t, err)
	return data
}

// startRefused asserts New refuses cfg/deps, naming why.
func startRefused(t *testing.T, cfg authkit.Config, deps authkit.Deps, reason string) {
	t.Helper()
	client, err := authkit.New(t.Context(), cfg, deps)
	if client != nil {
		_ = client.Close(context.Background())
	}
	if err == nil || !strings.Contains(err.Error(), reason) {
		t.Fatalf("New = %v, want a refusal naming %q", err, reason)
	}
}

func TestCriticalRuntime(t *testing.T) {
	t.Run("AK-J01-C01_concurrent_boot_preserves_one_authority", func(t *testing.T) {
		f := newFixture(t)
		u := f.user(t)
		t.Run("replicas", func(t *testing.T) {
			for _, name := range []string{"first", "second"} {
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					replica, err := authkit.New(t.Context(), f.cfg, f.deps)
					noError(t, err)
					t.Cleanup(func() { noError(t, replica.Close(context.Background())) })
					got, err := replica.User(t.Context(), iam.UserByID(u.ID))
					noError(t, err)
					if got.ID != u.ID || got.TenantID != f.tenant {
						t.Fatal("concurrent boot changed durable identity")
					}
				})
			}
		})
	})
	t.Run("AK-J01-C02_restart_validates_existing_schema", func(t *testing.T) {
		f := newFixture(t)
		u := f.user(t)
		session := f.signIn(t, u)
		noError(t, f.auth.Close(t.Context()))
		cfg := f.cfg
		cfg.Database.SkipMigrations = true
		restarted, err := authkit.New(t.Context(), cfg, f.deps)
		noError(t, err)
		t.Cleanup(func() { noError(t, restarted.Close(context.Background())) })
		got, err := restarted.User(t.Context(), iam.UserByID(u.ID))
		noError(t, err)
		if got.ID != u.ID {
			t.Fatal("restart lost committed account")
		}
		claims, err := restarted.Verify(t.Context(), session.AccessToken)
		noError(t, err)
		noError(t, restarted.CheckSession(t.Context(), claims))
		if err := restarted.Ready(t.Context()); err == nil {
			t.Fatal("unstarted required worker fleet reported ready")
		}
		noError(t, restarted.Start(context.Background()))
		noError(t, restarted.Ready(t.Context()))
	})
	t.Run("AK-J01-C03_missing_signer_or_database_fails_closed", func(t *testing.T) {
		f := newFixture(t)
		cfg := f.cfg
		cfg.Keys = authkit.KeysConfig{Path: t.TempDir()}
		deps := f.deps
		deps.KeySource = nil
		client, err := authkit.New(t.Context(), cfg, deps)
		if err == nil || client != nil {
			if client != nil {
				_ = client.Close(context.Background())
			}
			t.Fatal("deployment without a signer started")
		}
		noError(t, f.pool.Ping(t.Context()))
		bad, err := pgxpool.New(t.Context(), "postgres://critical:unreachable@127.0.0.1:1/critical?sslmode=disable&connect_timeout=1")
		noError(t, err)
		defer bad.Close()
		deps = f.deps
		deps.Postgres = bad
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		client, err = authkit.New(ctx, f.cfg, deps)
		if err == nil || client != nil {
			if client != nil {
				_ = client.Close(context.Background())
			}
			t.Fatal("deployment with unavailable durable store started")
		}
	})
	t.Run("AK-J01-C04_close_preserves_borrowed_pool_and_fleet", func(t *testing.T) {
		f := newFixture(t)
		fleet, err := riverkit.New(t.Context(), f.pool, &river.Config{Schema: f.schema}, f.auth.RiverJobs())
		noError(t, err)
		noError(t, fleet.Start(context.Background()))
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			noError(t, fleet.Stop(ctx))
		})
		noError(t, f.auth.Start(context.Background(), authkit.WithRiverClient(fleet)))
		noError(t, f.auth.Ready(t.Context()))
		view, err := f.auth.ForTenant(t.Context(), f.tenant)
		noError(t, err)
		noError(t, view.Close(t.Context()))
		noError(t, f.auth.Ready(t.Context()))
		if err := view.Start(t.Context()); err == nil {
			t.Fatal("tenant view took ownership of runtime lifecycle")
		}
		noError(t, f.auth.Close(t.Context()))
		noError(t, f.pool.Ping(t.Context()))
		select {
		case <-fleet.Stopped():
			t.Fatal("AuthKit closed its host-owned River fleet")
		default:
		}
	})
	t.Run("AK-J01-C05_writable_key_files_refuse_startup_and_reload", func(t *testing.T) {
		f := newFixture(t)
		deps := f.deps
		deps.KeySource = nil
		cfg := f.cfg
		for _, mode := range []os.FileMode{0o620, 0o602} {
			dir := t.TempDir()
			writeKeyFile(t, dir, "keys.json", keysJSON(t, "writable"), mode)
			cfg.Keys = authkit.KeysConfig{Path: dir}
			startRefused(t, cfg, deps, "group/world-writable")
		}
		dir := t.TempDir()
		writeKeyFile(t, dir, "keys.json", keysJSON(t, "readonly"), 0o440)
		writeKeyFile(t, dir, "totp.key", []byte(base64.StdEncoding.EncodeToString(make([]byte, 32))), 0o660)
		cfg.Keys = authkit.KeysConfig{Path: dir}
		cfg.TwoFactor.TOTPSecretKey = nil
		startRefused(t, cfg, deps, "group/world-writable")
		noError(t, os.Chmod(filepath.Join(dir, "totp.key"), 0o440))
		client, err := authkit.New(t.Context(), cfg, deps)
		noError(t, err)
		noError(t, client.Close(context.Background()))

		// A rotation rendered writable keeps serving the last good keys.
		dir = t.TempDir()
		writeKeyFile(t, dir, "keys.json", keysJSON(t, "first"), 0o600)
		src, err := keys.Watch(dir)
		noError(t, err)
		t.Cleanup(src.Close)
		writeKeyFile(t, dir, "keys.json", keysJSON(t, "second"), 0o660)
		if err := src.Reload(); err == nil || src.ActiveSigner().KID() != "first" {
			t.Fatalf("writable keys.json was swapped in: %v, active %s", err, src.ActiveSigner().KID())
		}
		noError(t, os.Chmod(filepath.Join(dir, "keys.json"), 0o600))
		noError(t, src.Reload())
		if src.ActiveSigner().KID() != "second" {
			t.Fatal("corrected keys.json was not loaded")
		}
	})
}
