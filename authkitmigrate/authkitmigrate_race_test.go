package authkitmigrate_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/open-rails/authkit/authkitmigrate"
	"github.com/open-rails/authkit/internal/testdb"
)

// Two migrators racing a fresh database (doujins runs its Postgres and
// ClickHouse migration groups in parallel goroutines, both tracking in
// public.migrations) used to lose the first CREATE TABLE IF NOT EXISTS to
// Postgres's concurrent-create race — "duplicate key value violates unique
// constraint pg_type_typname_nsp_index". Both calls must succeed and leave a
// single ledger.
func TestMigrateConcurrentOnFreshDatabase(t *testing.T) {
	const rounds = 20
	for i := 0; i < rounds; i++ {
		t.Run(fmt.Sprintf("round-%d", i), func(t *testing.T) {
			pg := testdb.EmptyScratchPostgres(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			start := make(chan struct{})
			errs := make([]error, 2)
			var wg sync.WaitGroup
			for j := range errs {
				wg.Add(1)
				go func(j int) {
					defer wg.Done()
					<-start
					_, errs[j] = authkitmigrate.New(pg.Pool, nil).Migrate(ctx)
				}(j)
			}
			close(start)
			wg.Wait()
			for j, err := range errs {
				if err != nil {
					t.Fatalf("migrator %d: %v", j, err)
				}
			}

			var rows, names int
			if err := pg.Pool.QueryRow(ctx,
				`SELECT count(*), count(DISTINCT name) FROM public.migrations WHERE app = 'authkit'`,
			).Scan(&rows, &names); err != nil {
				t.Fatal(err)
			}
			if rows == 0 || rows != names {
				t.Fatalf("ledger rows=%d distinct names=%d; want one row per migration", rows, names)
			}
			if err := authkitmigrate.New(pg.Pool, nil).Validate(ctx); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}
