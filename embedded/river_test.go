package embedded

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/internal/testdb"
)

func maintenanceConfig() Config {
	return Config{
		Keys:      KeysConfig{VerifyOnly: true},
		Token:     TokenConfig{Issuer: "https://maintenance.test", IssuedAudiences: []string{"test"}},
		Ephemeral: EphemeralConfig{AllowMemory: true},
		TwoFactor: TwoFactorConfig{Mode: TwoFactorDisabled},
	}
}

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
			require.NoError(t, ApplyMigrations(t.Context(), pg.Pool, "", MigrationOptions{RiverSchema: schema, RuntimePool: runtimePool}))
			_, err := pg.Pool.Exec(t.Context(), "REVOKE CREATE ON SCHEMA public FROM PUBLIC")
			require.NoError(t, err)
			assertMigrationRuntimeUser(t, runtimePool)
			cfg := maintenanceConfig()
			cfg.River = RiverConfig{Schema: schema, CleanupInterval: time.Second}
			core, err := New(cfg, Deps{Postgres: runtimePool})
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
	ownership := RiverFromHost()
	require.NoError(t, ApplyMigrations(t.Context(), pg.Pool, "", MigrationOptions{River: ownership}))
	var riverExists bool
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT to_regclass('public.river_job') IS NOT NULL").Scan(&riverExists))
	require.False(t, riverExists, "host mode must not migrate River")
	core, err := New(maintenanceConfig(), Deps{Postgres: pg.Pool, River: ownership})
	require.NoError(t, err)
	t.Cleanup(core.Close)
	require.Nil(t, core.maintenance.client, "host mode must not construct another River client")
	require.ErrorContains(t, core.Start(t.Context()), "RegisterRiver")
	hostCfg := &river.Config{Schema: "host_queue", Workers: river.NewWorkers(), Queues: map[string]river.QueueConfig{"host_jobs": {MaxWorkers: 1}}}
	hostWorker := &hostMaintenanceWorker{done: make(chan struct{}, 4)}
	river.AddWorker(hostCfg.Workers, hostWorker)
	hostCfg.PeriodicJobs = []*river.PeriodicJob{river.NewPeriodicJob(river.PeriodicInterval(time.Hour), func() (river.JobArgs, *river.InsertOpts) {
		return hostMaintenanceArgs{}, &river.InsertOpts{Queue: "host_jobs"}
	}, &river.PeriodicJobOpts{RunOnStart: true})}
	require.NoError(t, core.RegisterRiver(hostCfg))
	require.Equal(t, "host_queue", hostCfg.Schema, "host schema is authoritative")
	require.Len(t, hostCfg.PeriodicJobs, 2, "both library and host schedules share the leader")
	require.ErrorContains(t, core.RegisterRiver(hostCfg), "already registered")
	require.NoError(t, core.Start(t.Context()))
	_, err = pg.Pool.Exec(t.Context(), "CREATE SCHEMA host_queue")
	require.NoError(t, err)
	migrator, err := rivermigrate.New(riverpgxv5.New(pg.Pool), &rivermigrate.Config{Schema: hostCfg.Schema})
	require.NoError(t, err)
	_, err = migrator.Migrate(t.Context(), rivermigrate.DirectionUp, nil)
	require.NoError(t, err)
	host, err := river.NewClient(riverpgxv5.New(pg.Pool), hostCfg)
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

func TestRiverConstructionFailureDoesNotStartOrOwnHostPool(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	require.NoError(t, ApplyMigrations(t.Context(), pg.Pool, ""))
	cfg := maintenanceConfig()
	cfg.Ephemeral.AllowMemory = false
	core, err := New(cfg, Deps{Postgres: pg.Pool})
	require.Error(t, err)
	require.Nil(t, core)
	require.NoError(t, pg.Pool.Ping(t.Context()))
	var count int
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM public.river_job").Scan(&count))
	require.Zero(t, count)
}

func TestRiverWithoutPostgresAndInvalidConfig(t *testing.T) {
	core, err := New(maintenanceConfig(), Deps{})
	require.NoError(t, err)
	defer core.Close()
	require.NoError(t, core.Start(t.Context()))
	require.ErrorContains(t, core.RegisterRiver(&river.Config{}), "requires PostgreSQL")
	cfg := maintenanceConfig()
	cfg.River.Schema = "invalid;schema"
	_, err = New(cfg, Deps{})
	require.ErrorContains(t, err, "River.Schema")
	cfg = maintenanceConfig()
	cfg.River.CleanupInterval = -time.Hour
	_, err = New(cfg, Deps{})
	require.ErrorContains(t, err, "CleanupInterval")
}
