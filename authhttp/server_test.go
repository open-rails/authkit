package authhttp

import (
	"crypto"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/ratelimit"
	"github.com/stretchr/testify/require"
)

// testSigner is one RSA keypair shared by the package's test engines: explicit
// keys instead of AllowEphemeralDevKeys, which persists a keypair under the
// package directory.
var testSigner = sync.OnceValue(func() *jwtkit.RSASigner {
	s, err := jwtkit.NewRSASigner(2048, "test-kid")
	if err != nil {
		panic(err)
	}
	return s
})

func testKeys() embedded.KeysConfig {
	s := testSigner()
	return embedded.KeysConfig{Source: jwtkit.StaticKeySource{Active: s, Pubs: map[string]crypto.PublicKey{s.KID(): s.PublicKey()}}}
}

func newServerTestConfig() embedded.Config {
	return embedded.Config{
		Keys: testKeys(),
		Token: embedded.TokenConfig{
			Issuer:            "https://example.com",
			IssuedAudiences:   []string{"test-app"},
			ExpectedAudiences: []string{"test-app"},
		},
		Registration: embedded.RegistrationConfig{Verification: embedded.RegistrationVerificationNone},
		DeviceKeys:   embedded.DeviceKeysConfig{Enabled: true},
		// Environment empty => dev => signing keys are auto-generated.
	}
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
	pool := testdb.Pool(t)

	// Option takes effect at construction.
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool), WithoutRateLimiter())
	require.NoError(t, err)
	require.NotNil(t, srv.svc, "core engine wired")
	require.Nil(t, srv.rl, "WithoutRateLimiter option must be applied at construction")

	// Production without Redis fails at the ENGINE (#305): the memory ephemeral
	// store is refused before authhttp is ever reached.
	prodCfg := newServerTestConfig()
	prodCfg.Environment = "production"
	_, err = embedded.New(prodCfg, pool)
	require.Error(t, err, "production without a Redis store must fail engine construction")
	require.Contains(t, err.Error(), "Ephemeral.AllowMemory")

	// The explicit single-instance opt-in permits memory at both layers.
	memCfg := prodCfg
	memCfg.Ephemeral = embedded.EphemeralConfig{AllowMemory: true}
	memSrv, err := NewServer(newServerClient(t, memCfg, pool), WithDirectPeerIP())
	require.NoError(t, err, "Ephemeral.AllowMemory must permit the memory backends outside dev")
	memSrv.Close()

	// Production WITH Redis passes.
	rdb := testdb.ScratchRedis(t)
	_, err = NewServer(newServerClient(t, prodCfg, pool, embedded.WithRedis(rdb)), WithRedis(rdb), WithDirectPeerIP())
	require.NoError(t, err, "production with Redis must pass validation")
}

// #212: a "required" registration-verification policy with no email/SMS sender
// wired on the engine must fail NewServer with a construction ERROR — never a
// panic (the old behavior panicked later, at handler mount).
func TestNewServer_RequiredVerificationWithoutSender_ReturnsError(t *testing.T) {
	cfg := newServerTestConfig()
	cfg.Registration = embedded.RegistrationConfig{Verification: embedded.RegistrationVerificationRequired}

	// Engine built with NO email/SMS sender.
	client := newServerClient(t, cfg, testdb.UnlockedPool(t))

	// The call under test must return an error and must NOT panic; if it panicked
	// the test binary would crash, so reaching require.Error already proves no panic.
	srv, err := NewServer(client)
	require.Error(t, err, "Required verification without a sender must fail construction")
	require.Nil(t, srv)
	require.Contains(t, err.Error(), "no email or SMS sender")

	// Wiring a sender on the engine makes the same construction succeed.
	withSender := newServerClient(t, cfg, testdb.UnlockedPool(t), embedded.WithEmailSender(testEmailSender{}))
	srv, err = NewServer(withSender, WithoutRateLimiter())
	require.NoError(t, err, "Required verification with a sender must construct cleanly")
	require.NotNil(t, srv)
}

// #210: Redis is taken ONCE. When the engine has Redis wired (embedded.WithRedis)
// but the HTTP layer does NOT (no authhttp.WithRedis), NewServer reuses the
// engine's *redis.Client — single source of truth, no split-brain — and the
// production validation no longer flags a missing HTTP-side Redis.
func TestNewServer_ReusesEngineRedis(t *testing.T) {
	rdb := testdb.ScratchRedis(t)

	prodCfg := newServerTestConfig()
	prodCfg.Environment = "production"

	// Engine has Redis; NewServer gets NO authhttp.WithRedis. Production validation
	// (which previously only checked the HTTP side) must now pass via reuse.
	client := newServerClient(t, prodCfg, testdb.UnlockedPool(t), embedded.WithRedis(rdb))
	srv, err := NewServer(client, WithDirectPeerIP())
	require.NoError(t, err, "engine Redis must satisfy production validation without authhttp.WithRedis")
	require.NotNil(t, srv)
	require.Same(t, rdb, srv.rd, "HTTP layer must reuse the engine's *redis.Client (no split-brain)")

	// A second authhttp.WithRedis stays an explicit OVERRIDE, not a requirement.
	other := testdb.ScratchRedis(t)
	override, err := NewServer(
		newServerClient(t, prodCfg, testdb.UnlockedPool(t), embedded.WithRedis(rdb)),
		WithRedis(other), WithDirectPeerIP(),
	)
	require.NoError(t, err)
	require.Same(t, other, override.rd, "explicit authhttp.WithRedis must override the engine's client")
}

// #242: WithRateLimitOverrides merges bucket-specific limits onto
// DefaultRateLimits without replacing the whole table or the auto-selected
// backend — an untouched bucket keeps its default while the overridden one
// applies the overlay.
func TestNewServer_RateLimitOverrides(t *testing.T) {
	override := ratelimit.Limit{Limit: 3, Window: time.Minute}
	srv, err := NewServer(
		newServerClient(t, newServerTestConfig(), testdb.UnlockedPool(t)),
		WithRateLimitOverrides(map[string]ratelimit.Limit{RLPasswordLogin: override}),
	)
	require.NoError(t, err)

	rlr, ok := srv.rl.(RateLimiterWithResult)
	require.True(t, ok, "the auto-created limiter must implement RateLimiterWithResult")

	overridden, err := rlr.AllowNamedResult(RLPasswordLogin, "k1")
	require.NoError(t, err)
	require.Equal(t, override.Limit, overridden.Limit, "overridden bucket must use the overlay limit")
	require.Equal(t, override.Window, overridden.Window, "overridden bucket must use the overlay window")

	wantDefault := DefaultRateLimits()[RLAuthLogout]
	untouched, err := rlr.AllowNamedResult(RLAuthLogout, "k2")
	require.NoError(t, err)
	require.Equal(t, wantDefault.Limit, untouched.Limit, "untouched bucket must keep its default limit")
	require.Equal(t, wantDefault.Window, untouched.Window, "untouched bucket must keep its default window")
}
