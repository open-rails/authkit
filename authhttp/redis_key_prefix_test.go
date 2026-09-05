package authhttp

import (
	"context"
	"testing"

	"github.com/open-rails/authkit/authkitmigrate"
	"github.com/open-rails/authkit/internal/siws"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/oidckit"
	"github.com/stretchr/testify/require"
)

// #307: two servers over engines with different schemas share one Redis
// database; the rate limiter, the OIDC state cache and the SIWS cache all
// write under the engine's namespace and never collide.
func TestNewServer_RedisKeysAreNamespacedPerSchema(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	rdb := testdb.ScratchRedis(t)
	ctx := context.Background()

	schemas := []string{"tenant_a", "tenant_b"}
	for _, schema := range schemas {
		_, err := authkitmigrate.New(pg.Pool, &authkitmigrate.Config{Schema: schema}).Migrate(ctx)
		require.NoError(t, err)
		cfg := newServerTestConfig()
		cfg.Schema = schema
		srv, err := NewServer(newServerClient(t, cfg, pg.Pool, withRedis(rdb)))
		require.NoError(t, err)
		require.True(t, srv.allowResultForKey(RLPasswordLogin, RLPasswordLogin+":ip:203.0.113.9").Allowed)
		require.NoError(t, srv.stateCache().Put(ctx, "state-1", oidckit.StateData{}))
		require.NoError(t, srv.siwsCache().Put(ctx, "nonce-1", siws.ChallengeData{}))
	}
	for _, schema := range schemas {
		keys, err := rdb.Keys(ctx, "authkit:"+schema+":*").Result()
		require.NoError(t, err)
		require.ElementsMatch(t, []string{
			"authkit:" + schema + ":ratelimit:" + RLPasswordLogin + ":ip:203.0.113.9:" + RLPasswordLogin,
			"authkit:" + schema + ":oidc:state:state-1",
			"authkit:" + schema + ":siws:nonce:nonce-1",
		}, keys)
	}
	for _, pattern := range []string{"auth:*", "oidc:*", "siws:*", RLPasswordLogin + ":*"} {
		keys, err := rdb.Keys(ctx, pattern).Result()
		require.NoError(t, err)
		require.Empty(t, keys, "un-namespaced keys under %q", pattern)
	}
}
