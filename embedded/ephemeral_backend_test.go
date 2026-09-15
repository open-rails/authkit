package embedded

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	memorystore "github.com/open-rails/authkit/internal/storage/memory"
	redisstore "github.com/open-rails/authkit/internal/storage/redis"

	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// #305/#314: the per-process memory ephemeral store is refused unless
// Ephemeral.AllowMemory opts in; Redis always passes.
func TestNewRefusesMemoryEphemeralWithoutOptIn(t *testing.T) {
	pool := testdb.UnlockedPool(t)
	base := Config{
		Keys:         testKeys(t),
		Token:        TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"test-app"}, ExpectedAudiences: []string{"test-app"}},
		Registration: RegistrationConfig{Verification: RegistrationVerificationNone},
	}

	_, err := New(base, Deps{Postgres: pool})
	require.Error(t, err, "no Redis and no opt-in must refuse")
	require.Contains(t, err.Error(), "Ephemeral.AllowMemory")

	allowed := base
	allowed.Ephemeral = EphemeralConfig{AllowMemory: true}
	c, err := New(allowed, Deps{Postgres: pool})
	require.NoError(t, err)
	require.Equal(t, "memory", c.EphemeralBackend())

	rdb := testdb.ScratchRedis(t)
	c, err = New(base, Deps{Postgres: pool, Redis: rdb})
	require.NoError(t, err)
	require.Equal(t, "redis", c.EphemeralBackend())
}

// The shared primitive is the single-winner fence used after a proof has been
// checked. Redis and memory must preserve the same stale-reader semantics.
func TestEphemeralConditionalConsume(t *testing.T) {
	memory := memorystore.NewKV()
	t.Cleanup(memory.Close)
	stores := map[string]EphemeralStore{"memory": memory, "redis": redisstore.NewKV(testdb.ScratchRedis(t), "conditional:")}
	for name, store := range stores {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			require.NoError(t, store.Set(ctx, "proof", []byte("issuance-one"), time.Minute))
			previous, ok, err := store.Get(ctx, "proof")
			require.NoError(t, err)
			require.True(t, ok)
			require.NoError(t, store.Set(ctx, "proof", []byte("issuance-two"), time.Minute))
			won, err := store.CompareAndConsume(ctx, "proof", previous)
			require.NoError(t, err)
			require.False(t, won, "stale reader cannot consume reissued proof")
			won, err = store.CompareAndConsume(ctx, "other-purpose", []byte("issuance-two"))
			require.NoError(t, err)
			require.False(t, won)
			var wins atomic.Int32
			var wg sync.WaitGroup
			start := make(chan struct{})
			for range 16 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					won, err := store.CompareAndConsume(ctx, "proof", []byte("issuance-two"))
					if err != nil {
						t.Error(err)
					}
					if won {
						wins.Add(1)
					}
				}()
			}
			close(start)
			wg.Wait()
			require.EqualValues(t, 1, wins.Load())
			_, ok, err = store.Get(ctx, "proof")
			require.NoError(t, err)
			require.False(t, ok)
		})
	}
}
