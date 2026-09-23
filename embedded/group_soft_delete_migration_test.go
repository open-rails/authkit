package embedded

import (
	"database/sql"
	"testing"
	"testing/fstest"

	pgmigrations "github.com/open-rails/authkit/internal/migrations/postgres"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/migratekit"
	"github.com/stretchr/testify/require"
)

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
	require.NoError(t, ApplyMigrations(ctx, pg.Pool, "profiles"))
	require.NoError(t, ApplyMigrations(ctx, pg.Pool, "profiles"))
	descriptor, err := NewPermissionGroupStore(pg.Pool).GroupInstanceByID(ctx, group)
	require.NoError(t, err)
	require.Equal(t, "Existing group", descriptor.DisplayName)
	require.Nil(t, descriptor.DeletedAt)
	var canonical int
	require.NoError(t, pg.Pool.QueryRow(ctx, "SELECT count(*) FROM profiles.name_claims WHERE owner_id=$1::uuid AND canonical", group).Scan(&canonical))
	require.Equal(t, 1, canonical)
	_, err = pg.Pool.Exec(ctx, "UPDATE profiles.permission_groups SET deleted_at=now() WHERE id=$1::uuid", root)
	require.Error(t, err, "root remains active at the storage boundary")
}
