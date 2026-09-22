package embedded

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	pgmigrations "github.com/open-rails/authkit/internal/migrations/postgres"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/migratekit"
	"github.com/stretchr/testify/require"
)

func TestAccountDeletionUpgradePreservesPendingSites(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	migrations, err := migratekit.LoadFromFS(pgmigrations.FS)
	require.NoError(t, err)
	migrator, err := migratekit.NewPostgresFromPGXPool(pg.Pool, "authkit")
	require.NoError(t, err)
	require.NoError(t, migrator.WithSchema("profiles").ApplyMigrations(t.Context(), migrations[:1]))
	issuers := []string{"https://upgrade-first.example.test", "https://upgrade-second.example.test"}
	var activeID string
	var deletedAt time.Time
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "INSERT INTO profiles.users(deleted_at) VALUES (statement_timestamp()-interval '5 days') RETURNING id::text,deleted_at").Scan(&activeID, &deletedAt))
	purgedID := uuid.NewString()
	for _, id := range []string{activeID, purgedID} {
		_, err = pg.Pool.Exec(t.Context(), "INSERT INTO profiles.account_erasure_obligations(user_id,created_at,pending_sites) VALUES ($1::uuid,statement_timestamp()-interval '40 days',2)", id)
		require.NoError(t, err)
		_, err = pg.Pool.Exec(t.Context(), `INSERT INTO profiles.account_erasure_acknowledgements(user_id,issuer,obligation_created_at)
 SELECT user_id,issuer,created_at FROM profiles.account_erasure_obligations,unnest($2::text[]) issuer WHERE user_id=$1::uuid`, id, issuers)
		require.NoError(t, err)
	}
	require.NoError(t, ApplyMigrations(t.Context(), pg.Pool, ""))
	require.NoError(t, ApplyMigrations(t.Context(), pg.Pool, "", MigrationOptions{RiverSchema: "upgrade_sibling"}))
	var retained time.Time
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT deleted_at FROM profiles.account_deletions WHERE user_id=$1::uuid", activeID).Scan(&retained))
	require.True(t, deletedAt.Equal(retained), "upgrade must not reset an existing recovery deadline")
	var legacyTable *string
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT to_regclass('profiles.account_erasure_obligations')::text").Scan(&legacyTable))
	require.Nil(t, legacyTable)
	makeRuntime := func(issuer, schema string) *Runtime {
		t.Helper()
		cfg := maintenanceConfig()
		cfg.Token.Issuer, cfg.Token.AccountIssuers, cfg.River.Schema = issuer, issuers, schema
		runtime, err := New(cfg, Deps{Postgres: pg.Pool})
		require.NoError(t, err, "binding one site must not require its sibling to have started first")
		t.Cleanup(runtime.Close)
		return runtime
	}
	first := makeRuntime(issuers[0], "public")
	var adopted bool
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT jobs_enqueued FROM profiles.account_deletions WHERE user_id=$1::uuid", activeID).Scan(&adopted))
	require.False(t, adopted, "wait privately for every recorded delivery destination")
	second := makeRuntime(issuers[1], "upgrade_sibling")
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT jobs_enqueued FROM profiles.account_deletions WHERE user_id=$1::uuid", activeID).Scan(&adopted))
	require.True(t, adopted)
	require.NoError(t, first.Start(t.Context()))
	require.NoError(t, second.Start(t.Context()))
	require.Eventually(t, func() bool {
		var state string
		err := pg.Pool.QueryRow(context.Background(), "SELECT state FROM profiles.account_deletions WHERE user_id=$1::uuid", purgedID).Scan(&state)
		return err == nil && state == "purged"
	}, 15*time.Second, 25*time.Millisecond, "already-purged legacy identities still deliver pending host cleanup")
}
