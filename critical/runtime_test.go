package critical_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	stdlog "log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/keys"
	"github.com/open-rails/authkit/verify"
	riverkit "github.com/open-rails/helpers/river"
	"github.com/redis/go-redis/v9"
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
		src, err := keys.Watch(dir, nil)
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
	t.Run("AK-J01-C06_issuer_and_frontend_are_https_but_on_loopback", func(t *testing.T) {
		f := newFixture(t)
		for _, c := range []struct{ issuer, base string }{
			{"myapp", ""},
			{"myapp", "https://myapp.example"},
			{"http://myapp.example", ""},
			{"http://10.0.0.5:8080", ""},
			{"ftp://myapp.example", ""},
			{"https://myapp.example", "http://myapp.example"},
		} {
			cfg := f.cfg
			cfg.Issuer, cfg.FrontendURL = c.issuer, c.base
			startRefused(t, cfg, f.deps, "must be")
		}
		for _, issuer := range []string{"http://localhost:8080", "http://127.0.0.1:4780/auth", "http://[::1]:9000"} {
			cfg := f.cfg
			cfg.Issuer, cfg.FrontendURL = issuer, ""
			client, err := authkit.New(t.Context(), cfg, f.deps)
			noError(t, err)
			noError(t, client.Close(context.Background()))
		}
	})
	t.Run("AK-J01-C07_logs_only_through_the_injected_logger", func(t *testing.T) {
		stray := divertDefaultLog(t)
		logs := &logRecords{}
		logger := slog.New(logs)
		keyDir := t.TempDir()
		writeKeyFile(t, keyDir, "keys.json", keysJSON(t, "logged"), 0o444)
		if os.Getenv("AUTHKIT_TEST_REDIS_URL") == "" {
			t.Fatal("Redis fixture required")
		}
		u, err := url.Parse(os.Getenv("AUTHKIT_TEST_REDIS_URL"))
		noError(t, err)
		link := newDatabaseLink(t, u.Host)
		u.Host = link.listener.Addr().String()
		opts, err := redis.ParseURL(u.String())
		noError(t, err)
		opts.MaxRetries = -1
		opts.DialTimeout, opts.ReadTimeout, opts.WriteTimeout = time.Second, time.Second, time.Second
		rdb := redis.NewClient(opts)
		t.Cleanup(func() { _ = rdb.Close() })
		noError(t, rdb.Ping(t.Context()).Err())

		// A fresh schema: AuthKit's and River's migrators run, the signing
		// keys are world-readable, and AuthKit starts its own River fleet.
		f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) { c.Keys = authkit.KeysConfig{Path: keyDir} }),
			authtest.WithDeps(func(d *authkit.Deps) { d.Logger, d.KeySource, d.Redis = logger, nil, rdb }))
		noError(t, f.auth.Start(context.Background()))
		session := f.signIn(t, f.user(t))
		// A permission gate over the Client with no group on the request.
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/orders", nil)
		authtest.Authorize(t, f.auth, r, session.AccessToken)
		w := httptest.NewRecorder()
		verify.RequirePermission(f.auth, f.read)(http.NotFoundHandler()).ServeHTTP(w, r)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("ungrouped permission gate answered %d", w.Code)
		}
		// Redis goes away under the HTTP service's rate limiter.
		link.cut()
		f.call(t, "GET", "/capabilities", "", nil).want(t, http.StatusOK, "")
		_, err = authkit.ParseBootstrapManifestYAML([]byte("users:\n  - username: logged\n    email: logged@example.com\n    nickname: Logged\n"), logger)
		noError(t, err)
		noError(t, f.auth.Close(t.Context()))

		for _, want := range []string{
			"Applied migration",                // River's migrator
			"River client started",             // AuthKit's own River fleet
			"key file is world-readable",       // keys.Watch
			"RequirePermission found no group", // verify's gate, through Client.Logger
			"Redis rate limiting failed",       // the HTTP service
			"ignoring unknown key",             // the bootstrap manifest parser
		} {
			if !logs.has(want) {
				t.Errorf("Deps.Logger never heard %q", want)
			}
		}
		if got := stray.messages(); len(got) > 0 {
			t.Fatalf("AuthKit logged on slog.Default(): %q", got)
		}
	})
	t.Run("AK-J01-C08_development_keys_sign_only_for_a_loopback_issuer", func(t *testing.T) {
		f := newFixture(t)
		deps := f.deps
		deps.KeySource = nil
		local := f.cfg
		local.Issuer, local.FrontendURL = "http://localhost:4780", ""
		local.TwoFactor.TOTPSecretKey = nil

		// A loopback issuer generates its keys into the configured directory
		// (a Compose volume) and signs with them across restarts.
		dir := filepath.Join(t.TempDir(), "vault", "auth")
		local.Keys = authkit.KeysConfig{Path: dir}
		var signed []byte
		for range 2 {
			client, err := authkit.New(t.Context(), local, deps)
			noError(t, err)
			token, err := client.MintAccessToken(t.Context(), authtest.NewUser(t, client).ID, iam.AccessTokenOptions{})
			noError(t, err)
			_, err = client.Verify(t.Context(), token.Value)
			noError(t, err)
			noError(t, client.Close(context.Background()))
			keyFile, err := os.ReadFile(filepath.Join(dir, "keys.json"))
			noError(t, err)
			if signed != nil && string(signed) != string(keyFile) {
				t.Fatal("a restart regenerated the development keys")
			}
			signed = keyFile
		}

		// The same directory under a real issuer refuses to boot.
		production := f.cfg
		production.Keys = authkit.KeysConfig{Path: dir}
		production.TwoFactor.TOTPSecretKey = nil
		startRefused(t, production, deps, "development keys cannot sign for "+production.Issuer+": provision real keys")

		// A real issuer never generates, and provisioned keys serve any issuer.
		empty := t.TempDir()
		production.Keys = authkit.KeysConfig{Path: empty}
		startRefused(t, production, deps, "keys.json not found")
		if entries, err := os.ReadDir(empty); err != nil || len(entries) != 0 {
			t.Fatalf("a real issuer wrote keys: %v", err)
		}
		writeKeyFile(t, empty, "keys.json", keysJSON(t, "provisioned"), 0o600)
		for _, cfg := range []authkit.Config{production, local} {
			cfg.Keys = authkit.KeysConfig{Path: empty}
			client, err := authkit.New(t.Context(), cfg, deps)
			noError(t, err)
			noError(t, client.Close(context.Background()))
		}
	})
}

// logRecords is a slog.Handler keeping every record's message.
type logRecords struct {
	mu   sync.Mutex
	msgs []string
}

func (l *logRecords) Enabled(context.Context, slog.Level) bool { return true }
func (l *logRecords) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, r.Message)
	return nil
}
func (l *logRecords) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *logRecords) WithGroup(string) slog.Handler      { return l }

func (l *logRecords) messages() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.msgs)
}

func (l *logRecords) has(substr string) bool {
	return slices.ContainsFunc(l.messages(), func(m string) bool { return strings.Contains(m, substr) })
}

// divertDefaultLog points slog.Default(), and the standard library's log
// with it, at a recorder until the test ends.
func divertDefaultLog(t *testing.T) *logRecords {
	t.Helper()
	stray := &logRecords{}
	prev, out, flags := slog.Default(), stdlog.Writer(), stdlog.Flags()
	slog.SetDefault(slog.New(stray))
	t.Cleanup(func() {
		slog.SetDefault(prev)
		stdlog.SetOutput(out)
		stdlog.SetFlags(flags)
	})
	return stray
}
