package authhttp

import (
	"testing"

	"github.com/open-rails/authkit/internal/testdb"
	"github.com/redis/go-redis/v9"
)

// ephemeralStore is one leg of the store matrix: the in-memory ephemeral store
// (rdb nil) or a scratch Redis, the store production runs on.
type ephemeralStore struct {
	name string
	rdb  *redis.Client
}

// engineOpts wires the store onto embedded.New; NewServer then reuses the
// engine's Redis for its OIDC/SIWS caches and limiter (#210).
func (e ephemeralStore) engineOpts() []coreOpt {
	if e.rdb == nil {
		return nil
	}
	return []coreOpt{withRedis(e.rdb)}
}

// attach points a bare test Service (newTestService) at the store.
func (e ephemeralStore) attach(s *Service) *Service {
	s.rd = e.rdb
	return s
}

// forEachStore runs fn under the memory store and under a scratch Redis
// (AUTHKIT_TEST_REDIS_URL; always set in CI, where the skip gate enforces it),
// so every single-use / replay pin is proven against the production store.
func forEachStore(t *testing.T, fn func(t *testing.T, store ephemeralStore)) {
	t.Helper()
	t.Run("memory", func(t *testing.T) { fn(t, ephemeralStore{name: "memory"}) })
	t.Run("redis", func(t *testing.T) { fn(t, ephemeralStore{name: "redis", rdb: testdb.ScratchRedis(t)}) })
}
