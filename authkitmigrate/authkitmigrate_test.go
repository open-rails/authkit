package authkitmigrate_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit/authkitmigrate"
	"github.com/open-rails/authkit/internal/testdb"
)

func TestMigrator(t *testing.T) {
	pg := testdb.ScratchPostgres(t) // default schema already migrated the historical way
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	t.Run("default schema is already current under the historical tracking key", func(t *testing.T) {
		m := authkitmigrate.New(pg.Pool, nil)
		res, err := m.Migrate(ctx)
		if err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		if len(res.Applied) != 0 {
			t.Fatalf("expected no-op on harness-migrated db, applied %v", res.Applied)
		}
		if err := m.Validate(ctx); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	})

	t.Run("custom schema applies from scratch and is tracked separately", func(t *testing.T) {
		m := authkitmigrate.New(pg.Pool, &authkitmigrate.Config{Schema: "tenant_a"})

		if err := m.Validate(ctx); err == nil {
			t.Fatal("Validate should fail before migrating a fresh schema")
		}
		res, err := m.Migrate(ctx)
		if err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		if len(res.Applied) == 0 {
			t.Fatal("expected migrations applied for fresh schema")
		}
		if err := m.Validate(ctx); err != nil {
			t.Fatalf("Validate after Migrate: %v", err)
		}

		var exists bool
		err = pg.Pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'tenant_a' AND table_name = 'users')`,
		).Scan(&exists)
		if err != nil || !exists {
			t.Fatalf("tenant_a.users should exist (exists=%v, err=%v)", exists, err)
		}

		again, err := m.Migrate(ctx)
		if err != nil {
			t.Fatalf("second Migrate: %v", err)
		}
		if len(again.Applied) != 0 {
			t.Fatalf("second Migrate should be a no-op, applied %v", again.Applied)
		}
	})

	t.Run("second custom schema does not collide with the first", func(t *testing.T) {
		m := authkitmigrate.New(pg.Pool, &authkitmigrate.Config{Schema: "tenant_b"})
		res, err := m.Migrate(ctx)
		if err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		if len(res.Applied) == 0 {
			t.Fatal("tenant_b must migrate from scratch despite tenant_a being applied")
		}
	})

	t.Run("invalid schema is rejected", func(t *testing.T) {
		m := authkitmigrate.New(pg.Pool, &authkitmigrate.Config{Schema: "Bad-Schema"})
		if _, err := m.Migrate(ctx); err == nil || !strings.Contains(err.Error(), "invalid schema") {
			t.Fatalf("expected invalid schema error, got %v", err)
		}
	})
}
