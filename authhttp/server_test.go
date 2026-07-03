package authhttp

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/embedded"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func newServerTestConfig() embedded.Config {
	return embedded.Config{
		Keys: embedded.KeysConfig{AllowEphemeralDevKeys: true}, // #231: tests opt in explicitly
		Token: embedded.TokenConfig{
			Issuer:            "https://example.com",
			IssuedAudiences:   []string{"test-app"},
			ExpectedAudiences: []string{"test-app"},
		},
		Registration: embedded.RegistrationConfig{Verification: embedded.RegistrationVerificationNone},
		// Environment empty => dev => signing keys are auto-generated.
	}
}

func newServerTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AUTHKIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTHKIT_TEST_DATABASE_URL not set; skipping DB-backed test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	conn, err := pool.Acquire(context.Background())
	require.NoError(t, err)
	_, err = conn.Exec(context.Background(), `SELECT pg_advisory_lock(638476116)`)
	if err != nil {
		conn.Release()
	}
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock(638476116)`)
		conn.Release()
	})
	return pool
}

// newServerClient builds the embedded engine that a client-first NewServer wraps
// (#142). engineOpts are wired onto the client; HTTP-layer options stay on NewServer.
func newServerClient(t *testing.T, cfg embedded.Config, pool *pgxpool.Pool, engineOpts ...embedded.Option) *embedded.Client {
	t.Helper()
	c, err := embedded.New(cfg, pool, engineOpts...)
	require.NoError(t, err)
	return c
}

// #106: Postgres is mandatory — NewServer rejects a nil client and a client built
// without a Postgres pool (no DB needed; the check runs before any HTTP init).
func TestNewServer_RequiresPostgres(t *testing.T) {
	_, err := NewServer(nil)
	require.Error(t, err, "NewServer must reject a nil client")

	c, err := embedded.New(newServerTestConfig(), nil) // nil pg => no Postgres
	require.NoError(t, err)
	_, err = NewServer(c)
	require.Error(t, err, "NewServer must reject a client without Postgres")
}

// #108: functional options are applied INSIDE the constructor (before return),
// and #106: conditional validation rejects production without a Redis store.
func TestNewServer_OptionsAndConditionalValidation(t *testing.T) {
	pool := newServerTestPool(t)

	// Option takes effect at construction.
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool), WithoutRateLimiter())
	require.NoError(t, err)
	require.NotNil(t, srv.svc, "core engine wired")
	require.Nil(t, srv.rl, "WithoutRateLimiter option must be applied at construction")

	// Production without Redis fails conditional validation.
	prodCfg := newServerTestConfig()
	prodCfg.Environment = "production"
	_, err = NewServer(newServerClient(t, prodCfg, pool))
	require.Error(t, err, "production without a Redis store must fail validation")

	// Production WITH Redis passes (client is lazy; not contacted at construction).
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
	t.Cleanup(func() { _ = rdb.Close() })
	_, err = NewServer(newServerClient(t, prodCfg, pool), WithRedis(rdb))
	require.NoError(t, err, "production with Redis must pass validation")
}

// #212: a "required" registration-verification policy with no email/SMS sender
// wired on the engine must fail NewServer with a construction ERROR — never a
// panic (the old behavior panicked later, at handler mount).
func TestNewServer_RequiredVerificationWithoutSender_ReturnsError(t *testing.T) {
	cfg := newServerTestConfig()
	cfg.Registration = embedded.RegistrationConfig{Verification: embedded.RegistrationVerificationRequired}

	// Engine built with NO email/SMS sender.
	client := newServerClient(t, cfg, newNoDBPool(t))

	// The call under test must return an error and must NOT panic; if it panicked
	// the test binary would crash, so reaching require.Error already proves no panic.
	srv, err := NewServer(client)
	require.Error(t, err, "Required verification without a sender must fail construction")
	require.Nil(t, srv)
	require.Contains(t, err.Error(), "no email or SMS sender")

	// Wiring a sender on the engine makes the same construction succeed.
	withSender := newServerClient(t, cfg, newNoDBPool(t), embedded.WithEmailSender(testEmailSender{}))
	srv, err = NewServer(withSender, WithoutRateLimiter())
	require.NoError(t, err, "Required verification with a sender must construct cleanly")
	require.NotNil(t, srv)
}

// #210: Redis is taken ONCE. When the engine has Redis wired (embedded.WithRedis)
// but the HTTP layer does NOT (no authhttp.WithRedis), NewServer reuses the
// engine's *redis.Client — single source of truth, no split-brain — and the
// production validation no longer flags a missing HTTP-side Redis.
func TestNewServer_ReusesEngineRedis(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
	t.Cleanup(func() { _ = rdb.Close() })

	prodCfg := newServerTestConfig()
	prodCfg.Environment = "production"

	// Engine has Redis; NewServer gets NO authhttp.WithRedis. Production validation
	// (which previously only checked the HTTP side) must now pass via reuse.
	client := newServerClient(t, prodCfg, newNoDBPool(t), embedded.WithRedis(rdb))
	srv, err := NewServer(client)
	require.NoError(t, err, "engine Redis must satisfy production validation without authhttp.WithRedis")
	require.NotNil(t, srv)
	require.Same(t, rdb, srv.rd, "HTTP layer must reuse the engine's *redis.Client (no split-brain)")

	// A second authhttp.WithRedis stays an explicit OVERRIDE, not a requirement.
	other := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6380"})
	t.Cleanup(func() { _ = other.Close() })
	override, err := NewServer(
		newServerClient(t, prodCfg, newNoDBPool(t), embedded.WithRedis(rdb)),
		WithRedis(other),
	)
	require.NoError(t, err)
	require.Same(t, other, override.rd, "explicit authhttp.WithRedis must override the engine's client")
}

// #109: Server is an alias of Service — NewServer returns *Service, which is
// assignable to *Service (and vice versa).
func TestServerAlias_BackCompat(t *testing.T) {
	pool := newServerTestPool(t)
	svc, err := NewServer(newServerClient(t, newServerTestConfig(), pool))
	require.NoError(t, err)
	var _ *Service = svc // Server == Service (alias)
	var _ *Service = svc // both directions
}
