package embedded

import (
	"context"
	"testing"

	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// #307: two engines with different schemas on ONE Redis database derive
// disjoint key namespaces; an explicit KeyPrefix is honoured and validated.
func TestRedisKeyPrefixDerivesFromSchemaAndIsolates(t *testing.T) {
	pool := testdb.UnlockedPool(t)
	rdb := testdb.ScratchRedis(t)
	ctx := context.Background()
	base := Config{
		Keys:         KeysConfig{AllowEphemeralDevKeys: true},
		Token:        TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"test-app"}, ExpectedAudiences: []string{"test-app"}},
		Registration: RegistrationConfig{Verification: RegistrationVerificationNone},
	}

	clients := map[string]*Client{}
	for _, schema := range []string{"tenant_a", "tenant_b"} {
		cfg := base
		cfg.Schema = schema
		c, err := New(cfg, Deps{Postgres: pool, Redis: rdb})
		require.NoError(t, err)
		require.Equal(t, "authkit:"+schema+":", c.RedisKeyPrefix())
		require.Equal(t, "redis", c.EphemeralBackend())
		c.RecordFailedEmailVerifyCode(ctx, "shared@example.com")
		clients[schema] = c
	}
	for schema := range clients {
		keys, err := rdb.Keys(ctx, "authkit:"+schema+":*").Result()
		require.NoError(t, err)
		require.Len(t, keys, 1, "schema %s must own exactly its one key, got %v", schema, keys)
		require.Equal(t, "authkit:"+schema+":email_verify:attempts:shared@example.com", keys[0])
	}
	escaped, err := rdb.Keys(ctx, "email_verify:*").Result()
	require.NoError(t, err)
	require.Empty(t, escaped, "no key may be written outside its namespace")

	custom := base
	custom.Ephemeral.KeyPrefix = "app-one"
	c, err := New(custom, Deps{Postgres: pool, Redis: rdb})
	require.NoError(t, err)
	require.Equal(t, "app-one:", c.RedisKeyPrefix(), "a trailing ':' is added")

	bad := base
	bad.Ephemeral.KeyPrefix = "No Spaces Allowed"
	_, err = New(bad, Deps{Postgres: pool, Redis: rdb})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Ephemeral.KeyPrefix")
}
