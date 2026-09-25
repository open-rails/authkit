package embedded

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/internal/testclock"
	"github.com/open-rails/authkit/internal/testdb"
)

func ephemeralEngine(t *testing.T) *engine {
	t.Helper()
	pg := testdb.ScratchPostgres(t)
	core, err := newEngine(maintenanceConfig(), Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(core.Close)
	return core
}

// race starts n callers of fn together and returns how many won.
func race(t *testing.T, n int, fn func() (bool, error)) int {
	t.Helper()
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for range n {
		wg.Go(func() {
			<-start
			won, err := fn()
			assert.NoError(t, err)
			if won {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		})
	}
	close(start)
	wg.Wait()
	return wins
}

func TestEphemeralSingleUseUnderConcurrency(t *testing.T) {
	kv := ephemeralEngine(t).ephemeral
	ctx := t.Context()
	const callers, rounds = 16, 50
	for round := range rounds {
		key := fmt.Sprintf("consume:%d", round)
		require.NoError(t, kv.Set(ctx, key, []byte("secret"), time.Minute))
		wins := race(t, callers, func() (bool, error) {
			v, ok, err := kv.Consume(ctx, key)
			if ok {
				assert.Equal(t, []byte("secret"), v)
			}
			return ok, err
		})
		require.Equal(t, 1, wins, "round %d", round)

		key = fmt.Sprintf("cas:%d", round)
		require.NoError(t, kv.Set(ctx, key, []byte("current"), time.Minute))
		stale := race(t, callers, func() (bool, error) { return kv.CompareAndConsume(ctx, key, []byte("stale")) })
		require.Zero(t, stale, "a stale value must never claim")
		wins = race(t, callers, func() (bool, error) { return kv.CompareAndConsume(ctx, key, []byte("current")) })
		require.Equal(t, 1, wins, "round %d", round)
		_, ok, err := kv.Get(ctx, key)
		require.NoError(t, err)
		require.False(t, ok)
	}
}

func TestEphemeralIncrIsAtomicAndKeepsItsTTL(t *testing.T) {
	core := ephemeralEngine(t)
	kv, ctx := core.ephemeral, t.Context()
	const callers = 32
	var mu sync.Mutex
	var got []int64
	race(t, callers, func() (bool, error) {
		n, err := kv.Incr(ctx, "attempts", time.Minute)
		mu.Lock()
		got = append(got, n)
		mu.Unlock()
		return true, err
	})
	slices.Sort(got)
	for i, n := range got {
		require.Equal(t, int64(i+1), n)
	}

	expiry := func() time.Time {
		var at time.Time
		require.NoError(t, core.pg.QueryRow(ctx, `SELECT expires_at FROM ephemeral_kv WHERE key = 'attempts'`).Scan(&at))
		return at
	}
	first := expiry()
	_, err := kv.Incr(ctx, "attempts", time.Hour)
	require.NoError(t, err)
	require.Equal(t, first, expiry(), "Incr must not extend the counter's TTL")
	v, ok, err := kv.Get(ctx, "attempts")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, fmt.Sprint(callers+1), string(v))
}

func TestEphemeralExpiry(t *testing.T) {
	core := ephemeralEngine(t)
	clk := testclock.New()
	kv, ctx := &ephemeralKV{q: core.ephemeral.q, now: clk.Now}, t.Context()

	require.NoError(t, kv.Set(ctx, "code", []byte("v"), time.Minute))
	require.NoError(t, kv.Set(ctx, "cas", []byte("v"), time.Minute))
	n, err := kv.Incr(ctx, "counter", time.Minute)
	require.NoError(t, err)
	require.Equal(t, int64(1), n)
	_, err = kv.Incr(ctx, "counter", time.Minute)
	require.NoError(t, err)

	clk.Advance(time.Minute)
	_, ok, err := kv.Get(ctx, "code")
	require.NoError(t, err)
	require.False(t, ok, "an expired row is missing")
	_, ok, err = kv.Consume(ctx, "code")
	require.NoError(t, err)
	require.False(t, ok)
	claimed, err := kv.CompareAndConsume(ctx, "cas", []byte("v"))
	require.NoError(t, err)
	require.False(t, claimed)
	n, err = kv.Incr(ctx, "counter", time.Minute)
	require.NoError(t, err)
	require.Equal(t, int64(1), n, "an expired counter restarts")

	require.Error(t, kv.Set(ctx, "forever", []byte("v"), 0))
	_, err = kv.Incr(ctx, "forever", -time.Second)
	require.Error(t, err)

	// Without a host clock the database clock decides.
	require.NoError(t, core.ephemeral.Set(ctx, "db-clock", []byte("v"), time.Hour))
	_, err = core.pg.Exec(ctx, `UPDATE ephemeral_kv SET expires_at = now() - interval '1 millisecond' WHERE key = 'db-clock'`)
	require.NoError(t, err)
	_, ok, err = core.ephemeral.Consume(ctx, "db-clock")
	require.NoError(t, err)
	require.False(t, ok)
}

func TestEphemeralSweepPurgesOnlyExpiredRows(t *testing.T) {
	core := ephemeralEngine(t)
	ctx := t.Context()
	_, err := core.pg.Exec(ctx, `INSERT INTO ephemeral_kv (key, value, expires_at)
SELECT 'expired:' || i, '\x00', now() - interval '1 second' FROM generate_series(1, $1::int) i`, 2*ephemeralSweepBatch+5)
	require.NoError(t, err)
	require.NoError(t, core.ephemeral.Set(ctx, "live", []byte("v"), time.Hour))

	n, err := core.ephemeral.DeleteExpired(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(2*ephemeralSweepBatch+5), n)
	var rows int
	require.NoError(t, core.pg.QueryRow(ctx, `SELECT count(*) FROM ephemeral_kv`).Scan(&rows))
	require.Equal(t, 1, rows)
	_, ok, err := core.ephemeral.Get(ctx, "live")
	require.NoError(t, err)
	require.True(t, ok)
}

// The managed River periodic job purges expired rows and leaves live ones.
func TestEphemeralSweepRunsAsRiverMaintenance(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	runtimePool := migrationRuntimePool(t, pg)
	require.NoError(t, ApplyMigrations(t.Context(), pg.Pool, "", MigrationOptions{RuntimePool: runtimePool}))
	cfg := maintenanceConfig()
	cfg.River = RiverConfig{CleanupInterval: time.Second}
	core, err := newEngine(cfg, Deps{Postgres: runtimePool})
	require.NoError(t, err)
	t.Cleanup(core.Close)
	ctx := t.Context()
	expire := func(key string) {
		require.NoError(t, core.ephemeral.Set(ctx, key, []byte("v"), time.Hour))
		_, err := pg.Pool.Exec(ctx, `UPDATE profiles.ephemeral_kv SET expires_at = now() - interval '1 second' WHERE key = $1`, key)
		require.NoError(t, err)
	}
	purged := func(key string) func() bool {
		return func() bool {
			var exists bool
			err := pg.Pool.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM profiles.ephemeral_kv WHERE key = $1)`, key).Scan(&exists)
			return err == nil && !exists
		}
	}
	expire("expired:1")
	require.NoError(t, core.ephemeral.Set(ctx, "live", []byte("v"), time.Hour))
	require.NoError(t, core.Start(ctx))
	require.Eventually(t, purged("expired:1"), 15*time.Second, 25*time.Millisecond)
	// A second purge proves recurring scheduling, not just RunOnStart.
	expire("expired:2")
	require.Eventually(t, purged("expired:2"), 15*time.Second, 25*time.Millisecond)
	_, ok, err := core.ephemeral.Get(ctx, "live")
	require.NoError(t, err)
	require.True(t, ok, "the sweep must leave live rows")
}
