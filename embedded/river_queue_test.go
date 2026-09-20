package embedded

import (
	"context"
	"strings"
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

func TestMaintenanceQueueNames(t *testing.T) {
	// Construction does not connect. Exercise River's own queue/periodic-ID
	// validation through both library paths without requiring a database server.
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
			cfg.Ephemeral.KeyPrefix = "queue-test:" // This independent namespace need not include the full schema name.
			managed, err := New(cfg, Deps{Postgres: pool})
			require.NoError(t, err, "managed constructor must accept every valid schema")
			managed.Close()
			hosted, err := New(cfg, Deps{Postgres: pool, River: RiverFromHost()})
			require.NoError(t, err)
			defer hosted.Close()
			riverCfg := &river.Config{Schema: "public"}
			require.NoError(t, hosted.RegisterRiver(riverCfg))
			require.Contains(t, riverCfg.Queues, queue)
			_, err = river.NewClient(riverpgxv5.New(pool), riverCfg)
			require.NoError(t, err, "host constructor validates queue and periodic ID")
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
			var ownership *RiverOwnership
			if host {
				ownership = RiverFromHost()
			}
			require.NoError(t, ApplyMigrations(t.Context(), pg.Pool, schema, MigrationOptions{River: ownership}))
			cfg := maintenanceConfig()
			cfg.Schema = schema
			cfg.Ephemeral.KeyPrefix = "queue-test:" // This independent namespace need not include the full schema name.
			core, err := New(cfg, Deps{Postgres: pg.Pool, River: ownership})
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
				require.NoError(t, core.RegisterRiver(riverCfg))
				client, err := river.NewClient(riverpgxv5.New(pg.Pool), riverCfg)
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
