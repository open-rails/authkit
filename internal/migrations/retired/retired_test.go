package retired_test

import (
	"database/sql"
	"testing"

	pgmigrations "github.com/open-rails/authkit/internal/migrations/postgres"
	"github.com/open-rails/authkit/internal/migrations/retired"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/migratekit"
	"github.com/stretchr/testify/require"
)

// The baseline builds exactly what the retired chain built: the same tables,
// columns in the same order, types, defaults, constraints, indexes, views,
// functions, triggers, comments and grants. The conversion depends on it.
func TestBaselineBuildsTheRetiredChainsSchema(t *testing.T) {
	ctx := t.Context()
	pg := testdb.EmptyScratchPostgres(t)
	db, err := sql.Open("pgx", pg.URL)
	require.NoError(t, err)
	defer db.Close()

	tree, err := migratekit.LoadFromFS(pgmigrations.FS)
	require.NoError(t, err)
	baseline := tree[:1]
	require.Equal(t, "0001_schema.up.sql", baseline[0].Name)
	chain := retired.Chain()
	require.Len(t, chain, 15)
	require.NoError(t, migratekit.NewPostgres(db, "authkit").WithSchema("ak_retired_chain").ApplyMigrations(ctx, chain))
	require.NoError(t, migratekit.NewPostgres(db, "authkit").WithSchema("ak_baseline").ApplyMigrations(ctx, baseline))

	old, fresh := testdb.SchemaCatalog(t, db, "ak_retired_chain"), testdb.SchemaCatalog(t, db, "ak_baseline")
	require.Greater(t, len(fresh), 300)
	require.Contains(t, fresh, "relation users kind=r persistence=p options= rls=f acl= comment=")
	require.Empty(t, testdb.CatalogDiff(old, fresh))
	diff, err := migratekit.SchemaDiff(ctx, db, "ak_retired_chain", "ak_baseline")
	require.NoError(t, err)
	require.Empty(t, diff)
}
