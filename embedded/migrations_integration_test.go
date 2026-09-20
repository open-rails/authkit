package embedded

import (
	"context"
	"testing"

	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestApplyMigrationsCreatesSchemaBeforeClientConstruction(t *testing.T) {
	ctx := context.Background()
	pg := testdb.EmptyScratchPostgres(t)

	require.NoError(t, ApplyMigrations(ctx, pg.Pool, ""))
	var usersTable bool
	require.NoError(t, pg.Pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'profiles' AND table_name = 'users'
		)`).Scan(&usersTable))
	require.True(t, usersTable)

	client, err := NewWithKeys(
		Config{Token: TokenConfig{Issuer: "https://migrations.test"}},
		Keyset{},
		Deps{Postgres: pg.Pool},
	)
	require.NoError(t, err)
	client.Close()
}
