package critical_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	riverkit "github.com/open-rails/helpers/river"
	"github.com/riverqueue/river"
)

func TestCriticalRuntime(t *testing.T) {
	t.Run("AK-J01-C01_concurrent_boot_preserves_one_authority", func(t *testing.T) {
		f := newFixture(t)
		u := f.user(t)
		t.Run("replicas", func(t *testing.T) {
			for _, name := range []string{"first", "second"} {
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					replica, err := authkit.New(t.Context(), f.cfg, f.deps)
					noError(t, err)
					t.Cleanup(func() { noError(t, replica.Close(context.Background())) })
					got, err := replica.User(t.Context(), iam.UserByID(u.ID))
					noError(t, err)
					if got.ID != u.ID || got.TenantID != f.tenant {
						t.Fatal("concurrent boot changed durable identity")
					}
				})
			}
		})
	})
	t.Run("AK-J01-C02_restart_validates_existing_schema", func(t *testing.T) {
		f := newFixture(t)
		u := f.user(t)
		session := f.signIn(t, u)
		noError(t, f.auth.Close(t.Context()))
		cfg := f.cfg
		cfg.Database.SkipMigrations = true
		restarted, err := authkit.New(t.Context(), cfg, f.deps)
		noError(t, err)
		t.Cleanup(func() { noError(t, restarted.Close(context.Background())) })
		got, err := restarted.User(t.Context(), iam.UserByID(u.ID))
		noError(t, err)
		if got.ID != u.ID {
			t.Fatal("restart lost committed account")
		}
		claims, err := restarted.Verify(t.Context(), session.AccessToken)
		noError(t, err)
		noError(t, restarted.CheckSession(t.Context(), claims))
		if err := restarted.Ready(t.Context()); err == nil {
			t.Fatal("unstarted required worker fleet reported ready")
		}
		noError(t, restarted.Start(context.Background()))
		noError(t, restarted.Ready(t.Context()))
	})
	t.Run("AK-J01-C03_missing_signer_or_database_fails_closed", func(t *testing.T) {
		f := newFixture(t)
		cfg := f.cfg
		cfg.Keys = authkit.KeysConfig{Path: t.TempDir()}
		deps := f.deps
		deps.KeySource = nil
		client, err := authkit.New(t.Context(), cfg, deps)
		if err == nil || client != nil {
			if client != nil {
				_ = client.Close(context.Background())
			}
			t.Fatal("deployment without a signer started")
		}
		noError(t, f.pool.Ping(t.Context()))
		bad, err := pgxpool.New(t.Context(), "postgres://critical:unreachable@127.0.0.1:1/critical?sslmode=disable&connect_timeout=1")
		noError(t, err)
		defer bad.Close()
		deps = f.deps
		deps.Postgres = bad
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		client, err = authkit.New(ctx, f.cfg, deps)
		if err == nil || client != nil {
			if client != nil {
				_ = client.Close(context.Background())
			}
			t.Fatal("deployment with unavailable durable store started")
		}
	})
	t.Run("AK-J01-C04_close_preserves_borrowed_pool_and_fleet", func(t *testing.T) {
		f := newFixture(t)
		fleet, err := riverkit.New(t.Context(), f.pool, &river.Config{Schema: f.schema}, f.auth.RiverJobs())
		noError(t, err)
		noError(t, fleet.Start(context.Background()))
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			noError(t, fleet.Stop(ctx))
		})
		noError(t, f.auth.Start(context.Background(), authkit.WithRiverClient(fleet)))
		noError(t, f.auth.Ready(t.Context()))
		view, err := f.auth.ForTenant(t.Context(), f.tenant)
		noError(t, err)
		noError(t, view.Close(t.Context()))
		noError(t, f.auth.Ready(t.Context()))
		if err := view.Start(t.Context()); err == nil {
			t.Fatal("tenant view took ownership of runtime lifecycle")
		}
		noError(t, f.auth.Close(t.Context()))
		noError(t, f.pool.Ping(t.Context()))
		select {
		case <-fleet.Stopped():
			t.Fatal("AuthKit closed its host-owned River fleet")
		default:
		}
	})
}
