package engine

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	riverhelpers "github.com/open-rails/helpers/river"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/testdb"
)

func expiredEvent(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var id int64
	err := pool.QueryRow(t.Context(), `INSERT INTO profiles.session_events (occurred_at,issuer,user_id,session_id,event) VALUES (now()-interval '2 years','test','user','session','login') RETURNING id`).Scan(&id)
	require.NoError(t, err)
	return id
}

func awaitEventCleanup(t *testing.T, pool *pgxpool.Pool, id int64) {
	t.Helper()
	require.Eventually(t, func() bool {
		var exists bool
		err := pool.QueryRow(context.Background(), "SELECT EXISTS(SELECT 1 FROM profiles.session_events WHERE id=$1)", id).Scan(&exists)
		return err == nil && !exists
	}, 15*time.Second, 25*time.Millisecond)
}

func TestManagedRiverMaintenance(t *testing.T) {
	for _, schema := range []string{"public", "queue_jobs"} {
		t.Run(schema, func(t *testing.T) {
			pg := testdb.EmptyScratchPostgres(t)
			runtimePool := migrationRuntimePool(t, pg)
			require.NoError(t, Migrate(t.Context(), pg.Pool, config.Config{River: config.RiverConfig{Schema: schema}}, config.MigrateOptions{RuntimePool: runtimePool}))
			_, err := pg.Pool.Exec(t.Context(), "REVOKE CREATE ON SCHEMA public FROM PUBLIC")
			require.NoError(t, err)
			assertMigrationRuntimeUser(t, runtimePool)
			cfg := maintenanceConfig()
			cfg.River = config.RiverConfig{Schema: schema, CleanupInterval: time.Second}
			core, err := New(t.Context(), cfg, config.Deps{Postgres: runtimePool})
			require.NoError(t, err)
			t.Cleanup(core.Close)
			id := expiredEvent(t, pg.Pool)
			var count int
			require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM "+pgx.Identifier{schema}.Sanitize()+".river_job").Scan(&count))
			require.Zero(t, count, "New must neither enqueue nor start workers")
			require.NoError(t, core.Start(t.Context()))
			awaitEventCleanup(t, pg.Pool, id)
			// A second deletion proves recurring scheduling, not just RunOnStart.
			awaitEventCleanup(t, pg.Pool, expiredEvent(t, pg.Pool))
			core.Close()
			select {
			case <-core.maintenance.client.Stopped():
			default:
				t.Fatal("owned River client did not stop")
			}
			require.NoError(t, runtimePool.Ping(t.Context()), "host pool remains host owned")
			require.ErrorContains(t, core.Start(t.Context()), "closed")
		})
	}
}

type hostMaintenanceArgs struct{}

func (hostMaintenanceArgs) Kind() string { return "test_host_maintenance" }

type hostMaintenanceWorker struct {
	river.WorkerDefaults[hostMaintenanceArgs]
	done chan struct{}
}

func (w *hostMaintenanceWorker) Work(context.Context, *river.Job[hostMaintenanceArgs]) error {
	w.done <- struct{}{}
	return nil
}

func TestHostRiverMaintenanceComposition(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	cfg := maintenanceConfig()
	cfg.River.HostOwned = true
	require.NoError(t, Migrate(t.Context(), pg.Pool, cfg, config.MigrateOptions{}))
	var riverExists bool
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT to_regclass('public.river_job') IS NOT NULL").Scan(&riverExists))
	require.False(t, riverExists, "host mode must not migrate River")
	core, err := New(t.Context(), cfg, config.Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(core.Close)
	require.Nil(t, core.maintenance.client, "host mode must not construct another River client")
	require.ErrorContains(t, core.Start(t.Context()), "RiverJobs")
	hostCfg := &river.Config{Schema: "host_queue", Workers: river.NewWorkers(), Queues: map[string]river.QueueConfig{"host_jobs": {MaxWorkers: 1}}}
	hostWorker := &hostMaintenanceWorker{done: make(chan struct{}, 4)}
	river.AddWorker(hostCfg.Workers, hostWorker)
	hostCfg.PeriodicJobs = []*river.PeriodicJob{river.NewPeriodicJob(river.PeriodicInterval(time.Hour), func() (river.JobArgs, *river.InsertOpts) {
		return hostMaintenanceArgs{}, &river.InsertOpts{Queue: "host_jobs"}
	}, &river.PeriodicJobOpts{RunOnStart: true})}
	host, err := riverhelpers.New(t.Context(), pg.Pool, hostCfg, core.RiverJobs())
	require.NoError(t, err)
	require.Equal(t, "host_queue", hostCfg.Schema, "host schema is authoritative")
	require.Len(t, hostCfg.PeriodicJobs, 1, "composer preserves the caller configuration")
	_, err = riverhelpers.New(t.Context(), pg.Pool, hostCfg, core.RiverJobs())
	require.ErrorContains(t, err, "already composed")
	require.NoError(t, core.Start(t.Context()))
	_, err = pg.Pool.Exec(t.Context(), "CREATE SCHEMA host_queue")
	require.NoError(t, err)
	migrator, err := rivermigrate.New(riverpgxv5.New(pg.Pool), &rivermigrate.Config{Schema: hostCfg.Schema})
	require.NoError(t, err)
	_, err = migrator.Migrate(t.Context(), rivermigrate.DirectionUp, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, host.StopAndCancel(context.Background())) })
	id := expiredEvent(t, pg.Pool)
	require.NoError(t, host.Start(t.Context()))
	awaitEventCleanup(t, pg.Pool, id)
	select {
	case <-hostWorker.done:
	case <-time.After(15 * time.Second):
		t.Fatal("host periodic job did not run")
	}
	core.Close()
	_, err = host.Insert(t.Context(), hostMaintenanceArgs{}, &river.InsertOpts{Queue: "host_jobs"})
	require.NoError(t, err)
	select {
	case <-hostWorker.done:
	case <-time.After(15 * time.Second):
		t.Fatal("AuthKit Close stopped the host client")
	}
	require.NoError(t, pg.Pool.Ping(t.Context()))
}

func TestRiverWithoutPostgresAndInvalidConfig(t *testing.T) {
	core, err := New(t.Context(), maintenanceConfig(), config.Deps{})
	require.NoError(t, err)
	defer core.Close()
	require.NoError(t, core.Start(t.Context()))
	pool, err := pgxpool.New(t.Context(), "postgres://unused@127.0.0.1:1/unused?sslmode=disable")
	require.NoError(t, err)
	defer pool.Close()
	_, err = riverhelpers.New(t.Context(), pool, nil, core.RiverJobs())
	require.ErrorContains(t, err, "requires PostgreSQL")
	cfg := maintenanceConfig()
	cfg.River.Schema = "invalid;schema"
	_, err = New(t.Context(), cfg, config.Deps{})
	require.ErrorContains(t, err, "River.Schema")
	cfg = maintenanceConfig()
	cfg.River.CleanupInterval = -time.Hour
	_, err = New(t.Context(), cfg, config.Deps{})
	require.ErrorContains(t, err, "CleanupInterval")
}

func TestRiverJobsFailureInvalidatesPartialBindingAndPreservesHostPool(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	cfg := maintenanceConfig()
	cfg.River.HostOwned = true
	require.NoError(t, Migrate(t.Context(), pg.Pool, cfg, config.MigrateOptions{}))
	core, err := New(t.Context(), cfg, config.Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	defer core.Close()
	fail := riverhelpers.NewContribution("fail", func(context.Context, *river.Config) error { return nil }, func(context.Context, riverhelpers.Binding) error { return fmt.Errorf("binding failed") }, func() error { return nil })
	client, err := riverhelpers.New(t.Context(), pg.Pool, nil, core.RiverJobs(), fail)
	require.ErrorContains(t, err, "binding failed")
	require.Nil(t, client)
	require.Nil(t, core.maintenance.client)
	require.ErrorContains(t, core.Start(t.Context()), "RiverJobs")
	_, err = riverhelpers.New(t.Context(), pg.Pool, nil, core.RiverJobs())
	require.ErrorContains(t, err, "already composed")
	require.NoError(t, pg.Pool.Ping(t.Context()))
}

func TestClosedRiverJobsCannotCompose(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	cfg := maintenanceConfig()
	cfg.River.HostOwned = true
	require.NoError(t, Migrate(t.Context(), pg.Pool, cfg, config.MigrateOptions{}))
	core, err := New(t.Context(), cfg, config.Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	core.Close()
	_, err = riverhelpers.New(t.Context(), pg.Pool, nil, core.RiverJobs())
	require.ErrorContains(t, err, "closed")
	require.NoError(t, pg.Pool.Ping(t.Context()))
}

func TestMaintenanceQueueNames(t *testing.T) {
	// Registration validates River's queue/periodic IDs without connecting.
	// Binding additionally registers durable lifecycle destinations, so the
	// managed and host binding paths use real databases in the workflow below.
	pool, err := pgxpool.New(t.Context(), "postgres://localhost/authkit_queue_validation")
	require.NoError(t, err)
	defer pool.Close()
	schemas := []string{"profiles", strings.Repeat("a", 44), strings.Repeat("a", 45), strings.Repeat("a", 63), strings.Repeat("a", 62) + "b", "hosted_issuer_" + strings.Repeat("f", 32), "_private", "trailing_", "double__underscore"}
	seen := make(map[string]string)
	for _, schema := range schemas {
		t.Run(schema, func(t *testing.T) {
			queue := maintenanceQueue(schema)
			require.LessOrEqual(t, len(queue), 64)
			require.Equal(t, queue, maintenanceQueue(schema), "queue identity must be stable")
			require.Empty(t, seen[queue], "different schemas must use different queues")
			seen[queue] = schema
			if len(schema) <= 44 && !strings.HasPrefix(schema, "_") && !strings.HasSuffix(schema, "_") && !strings.Contains(schema, "__") {
				require.Equal(t, "authkit_maintenance_"+schema, queue, "preserve accepted existing names")
			}
			cfg := maintenanceConfig()
			cfg.Schema = schema
			cfg.River.HostOwned = true
			// Without a database New boots nothing; registration reads only
			// the configuration and the host-mode binding.
			hosted, err := New(t.Context(), cfg, config.Deps{})
			require.NoError(t, err)
			defer hosted.Close()
			hosted.maintenance = &riverMaintenance{fromHost: true}
			riverCfg := &river.Config{Schema: "public"}
			require.NoError(t, hosted.registerRiver(riverCfg))
			_, err = river.NewClient(riverpgxv5.New(pool), riverCfg)
			require.NoError(t, err, "River validates every worker queue and periodic ID")
		})
	}
}

func TestLongIdentitySchemaRunsRiverCleanup(t *testing.T) {
	schema := "s" + strings.Repeat("x", 62)
	for _, host := range []bool{false, true} {
		mode := "managed"
		if host {
			mode = "host"
		}
		t.Run(mode, func(t *testing.T) {
			pg := testdb.EmptyScratchPostgres(t)
			cfg := maintenanceConfig()
			cfg.Schema = schema
			cfg.River.HostOwned = host
			require.NoError(t, Migrate(t.Context(), pg.Pool, cfg, config.MigrateOptions{}))
			core, err := New(t.Context(), cfg, config.Deps{Postgres: pg.Pool})
			require.NoError(t, err)
			defer core.Close()
			var id int64
			table := pgx.Identifier{schema, "session_events"}.Sanitize()
			require.NoError(t, pg.Pool.QueryRow(t.Context(), "INSERT INTO "+table+" (occurred_at,issuer,user_id,session_id,event) VALUES (now()-interval '2 years','test','user','session','login') RETURNING id").Scan(&id))
			if host {
				migrator, err := rivermigrate.New(riverpgxv5.New(pg.Pool), &rivermigrate.Config{Schema: "public"})
				require.NoError(t, err)
				_, err = migrator.Migrate(t.Context(), rivermigrate.DirectionUp, nil)
				require.NoError(t, err)
				riverCfg := &river.Config{Schema: "public"}
				client, err := riverhelpers.New(t.Context(), pg.Pool, riverCfg, core.RiverJobs())
				require.NoError(t, err)
				require.NoError(t, core.Start(t.Context()))
				require.NoError(t, client.Start(t.Context()))
				defer func() { require.NoError(t, client.StopAndCancel(context.Background())) }()
			} else {
				require.NoError(t, core.Start(t.Context()))
			}
			require.Eventually(t, func() bool {
				var remains bool
				err := pg.Pool.QueryRow(context.Background(), "SELECT EXISTS(SELECT 1 FROM "+table+" WHERE id=$1)", id).Scan(&remains)
				return err == nil && !remains
			}, 15*time.Second, 25*time.Millisecond, "scheduled cleanup must reach the full-length identity schema")
		})
	}
}
