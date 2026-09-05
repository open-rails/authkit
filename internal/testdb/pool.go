package testdb

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testLockKey is the advisory lock every DB-backed test takes so packages that
// share the integration database never interleave their fixtures.
const testLockKey = 638476116

// Pool connects to the shared, already-migrated integration database (URL) and
// holds the cross-package advisory lock for the test's lifetime; Cleanup
// releases both. Skips (or fails under AUTHKIT_TEST_REQUIRE_DB=1) without a URL.
func Pool(t testing.TB) *pgxpool.Pool {
	t.Helper()
	return lock(t, connect(t, nil))
}

// PoolWithTracer is Pool with a pgx QueryTracer on every connection, for tests
// that count the queries a flow issues.
func PoolWithTracer(t testing.TB, tracer pgx.QueryTracer) *pgxpool.Pool {
	t.Helper()
	return lock(t, connect(t, tracer))
}

// UnlockedPool connects without the advisory lock, so a test may hold several
// pools at once or run next to a locked one.
func UnlockedPool(t testing.TB) *pgxpool.Pool {
	t.Helper()
	return connect(t, nil)
}

func connect(t testing.TB, tracer pgx.QueryTracer) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(URL(t))
	if err != nil {
		t.Fatalf("parse test database url: %v", err)
	}
	if tracer != nil {
		cfg.ConnConfig.Tracer = tracer
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("connect test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func lock(t testing.TB, pool *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire test db lock connection: %v", err)
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, testLockKey); err != nil {
		conn.Release()
		t.Fatalf("acquire test db lock: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, testLockKey)
		conn.Release()
	})
	return pool
}
