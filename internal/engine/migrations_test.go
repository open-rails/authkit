package engine

import (
	"context"
	"database/sql"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit/internal/ident"
	pgmigrations "github.com/open-rails/authkit/internal/migrations/postgres"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/migratekit"
	"github.com/stretchr/testify/require"
)

func TestMigrateSerializesManagedRiverWithSingleConnectionPool(t *testing.T) {
	for _, schema := range []string{"public", "shared_jobs"} {
		t.Run(schema, func(t *testing.T) {
			pg := testdb.EmptyScratchPostgres(t)
			runtimePool := migrationRuntimePool(t, pg)
			cfg := pg.Pool.Config()
			cfg.MaxConns = 1
			pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
			require.NoError(t, err)
			defer pool.Close()
			// This test deadline catches holding a pooled advisory-lock connection
			// while waiting for another connection from that same single-slot pool.
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			start := make(chan struct{})
			results := make(chan error, 6)
			for range 6 {
				go func() {
					<-start
					results <- Migrate(ctx, pool, MigrateOptions{Schema: "profiles", RiverSchema: schema, RuntimePool: runtimePool})
				}()
			}
			close(start)
			for range 6 {
				require.NoError(t, <-results)
			}
			var exists bool
			require.NoError(t, pool.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", schema+".river_job").Scan(&exists))
			require.True(t, exists)
			require.NoError(t, Migrate(ctx, pool, MigrateOptions{Schema: "profiles", RiverSchema: schema, RuntimePool: runtimePool}))
			assertMigrationRuntimeUser(t, runtimePool)
		})
	}
}

func TestGroupSoftDeleteMigrationUpgradesPublishedBaseline(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	ctx := t.Context()
	source, err := pgmigrations.FS.ReadFile("0001_schema.up.sql")
	require.NoError(t, err)
	baseline, err := migratekit.LoadFromFS(fstest.MapFS{"0001_schema.up.sql": &fstest.MapFile{Data: source}})
	require.NoError(t, err)
	database, err := sql.Open("pgx", pg.URL)
	require.NoError(t, err)
	defer database.Close()
	require.NoError(t, migratekit.NewPostgres(database, "authkit").WithSchema("profiles").ApplyMigrations(ctx, baseline))
	var root, group string
	require.NoError(t, pg.Pool.QueryRow(ctx, "INSERT INTO profiles.permission_groups(persona) VALUES('root') RETURNING id::text").Scan(&root))
	_, err = pg.Pool.Exec(ctx, "INSERT INTO profiles.group_persona_parents(persona,parent_persona) VALUES('channel','root')")
	require.NoError(t, err)
	require.NoError(t, pg.Pool.QueryRow(ctx, "INSERT INTO profiles.permission_groups(persona,parent_id,instance_slug,display_name) VALUES('channel',$1::uuid,'existing','Existing group') RETURNING id::text", root).Scan(&group))
	require.NoError(t, Migrate(ctx, pg.Pool, MigrateOptions{Schema: "profiles"}))
	require.NoError(t, Migrate(ctx, pg.Pool, MigrateOptions{Schema: "profiles"}))
	descriptor, err := newPermissionGroupStore(pg.Pool).groupByID(ctx, group)
	require.NoError(t, err)
	require.Equal(t, ident.Persona("channel"), descriptor.Persona)
	require.Nil(t, descriptor.DeletedAt)
	var claims int
	require.NoError(t, pg.Pool.QueryRow(ctx, "SELECT count(*) FROM profiles.name_claims WHERE owner_id=$1::uuid", group).Scan(&claims))
	require.Zero(t, claims, "groups keep no names")
	_, err = pg.Pool.Exec(ctx, "UPDATE profiles.permission_groups SET deleted_at=now() WHERE id=$1::uuid", root)
	require.Error(t, err, "root remains active at the storage boundary")
	var containment int
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM information_schema.columns WHERE table_schema='profiles' AND table_name='permission_groups' AND column_name='parent_id')
		+ (SELECT count(*) FROM information_schema.tables WHERE table_schema='profiles' AND table_name='group_persona_parents')`).Scan(&containment))
	require.Zero(t, containment, "0005 drops the stored containment tree")
	_, err = pg.Pool.Exec(ctx, "INSERT INTO profiles.permission_groups(persona) VALUES('channel')")
	require.NoError(t, err, "0011: a group is an id and a persona")
}
