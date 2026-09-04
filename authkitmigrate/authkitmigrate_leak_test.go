package authkitmigrate_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/authkitmigrate"
	"github.com/open-rails/authkit/internal/testdb"
)

// #302: migrating through a host pool must leave no migration session state
// (lock_timeout / statement_timeout) on any connection the host later gets,
// and must not borrow host-pool connections at all.
func TestMigrateLeavesNoSessionSettingsInHostPool(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	before := pg.Pool.Stat().TotalConns()
	res, err := authkitmigrate.New(pg.Pool, &authkitmigrate.Config{Schema: "leak_check"}).Migrate(ctx)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if len(res.Applied) == 0 {
		t.Fatal("expected a fresh schema to apply migrations through the host pool")
	}
	if after := pg.Pool.Stat().TotalConns(); after != before {
		t.Fatalf("host pool grew from %d to %d connections during Migrate; the runner must use its own sessions", before, after)
	}

	max := int(pg.Pool.Stat().MaxConns())
	conns := make([]*pgxpool.Conn, 0, max)
	defer func() {
		for _, c := range conns {
			c.Release()
		}
	}()
	for i := 0; i < max; i++ {
		c, err := pg.Pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("acquire %d/%d: %v", i, max, err)
		}
		conns = append(conns, c)
		for _, setting := range []string{"statement_timeout", "lock_timeout"} {
			var v string
			if err := c.QueryRow(ctx, "SHOW "+setting).Scan(&v); err != nil {
				t.Fatal(err)
			}
			if v != "0" {
				t.Fatalf("conn %d: %s=%q leaked from the migration session", i, setting, v)
			}
		}
	}
}
