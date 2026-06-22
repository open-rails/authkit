package authhttp

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	core "github.com/open-rails/authkit/core"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func newServerTestConfig() core.Config {
	return core.Config{
		Token: core.TokenConfig{
			Issuer:            "https://example.com",
			IssuedAudiences:   []string{"test-app"},
			ExpectedAudiences: []string{"test-app"},
		},
		Registration: core.RegistrationConfig{Verification: core.RegistrationVerificationNone},
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
	return pool
}

// #106: Postgres is a required positional argument — a nil pool is rejected at
// construction (no DB needed; the nil-check runs before any core init).
func TestNewServer_RequiresPostgres(t *testing.T) {
	_, err := NewServer(newServerTestConfig(), nil)
	require.Error(t, err, "NewServer must reject a nil *pgxpool.Pool")
}

// #108: functional options are applied INSIDE the constructor (before return),
// and #106: conditional validation rejects production without a Redis store.
func TestNewServer_OptionsAndConditionalValidation(t *testing.T) {
	pool := newServerTestPool(t)

	// Option takes effect at construction.
	srv, err := NewServer(newServerTestConfig(), pool, WithoutRateLimiter())
	require.NoError(t, err)
	require.NotNil(t, srv.Core(), "core service wired")
	require.Nil(t, srv.rl, "WithoutRateLimiter option must be applied at construction")

	// Production without Redis fails conditional validation.
	prodCfg := newServerTestConfig()
	prodCfg.Environment = "production"
	_, err = NewServer(prodCfg, pool)
	require.Error(t, err, "production without a Redis store must fail validation")

	// Production WITH Redis passes (client is lazy; not contacted at construction).
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
	t.Cleanup(func() { _ = rdb.Close() })
	_, err = NewServer(prodCfg, pool, WithRedis(rdb))
	require.NoError(t, err, "production with Redis must pass validation")
}

// #109: Server is an alias of Service — NewServer returns *Server, which is
// assignable to *Service (and vice versa).
func TestServerAlias_BackCompat(t *testing.T) {
	pool := newServerTestPool(t)
	svc, err := NewServer(newServerTestConfig(), pool)
	require.NoError(t, err)
	var _ *Server = svc  // Server == Service (alias)
	var _ *Service = svc // both directions
}
