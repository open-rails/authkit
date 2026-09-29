package engine

import (
	"context"
	"testing"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// TestAccountPurgeSweepsCredentialsBeforeTheRowGoes (H1): PurgeUsers is the
// operator's; it closes the recovery window at once, and once the row goes no
// key the account issued is live, including one no earlier sweep saw.
func TestAccountPurgeSweepsCredentialsBeforeTheRowGoes(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	require.NoError(t, Migrate(t.Context(), pg.Pool, MigrateOptions{}))
	runtime, err := New(context.Background(), maintenanceConfig(), Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(runtime.Close)
	ctx := t.Context()
	user, err := runtime.createUser(ctx, "purged@example.test", "purgeduser")
	require.NoError(t, err)
	var rootID string
	require.NoError(t, runtime.withAuthorityMutation(ctx, func(st *permissionGroupStore) error {
		rootID, err = runtime.rootGroup(ctx, st)
		return err
	}))
	key := func(name string) string {
		t.Helper()
		var id string
		require.NoError(t, pg.Pool.QueryRow(ctx, `INSERT INTO profiles.api_keys (permission_group_id,key_id,secret_hash,name,created_by,role)
 VALUES ($1::uuid,$2,'\x00'::bytea,$2,$3::uuid,'owner') RETURNING id::text`, rootID, name+"-"+user.ID[:8], user.ID).Scan(&id))
		return id
	}
	revoked := func(id string) bool {
		t.Helper()
		var live bool
		require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM profiles.api_keys WHERE id=$1::uuid AND revoked_at IS NULL)`, id).Scan(&live))
		return !live
	}
	issued := key("issued")

	_, err = runtime.PurgeUsers(ctx, iam.UserActor(user.ID), []string{user.ID})
	require.ErrorIs(t, err, iam.ErrInsufficientRoleAuthority, "purge is the operator's")
	require.NoError(t, itemErr(runtime.PurgeUsers(ctx, iam.OperatorActor(), []string{user.ID})))
	require.True(t, revoked(issued), "the soft delete sweeps the account's keys")
	restore, err := runtime.RestoreUsers(ctx, iam.OperatorActor(), []string{user.ID})
	require.NoError(t, err)
	require.Error(t, restore[0].Err, "a purge closes the recovery window")

	// A key no sweep has seen: only the purge-time sweep can revoke it.
	leftover := key("leftover")
	require.NoError(t, runtime.Start(ctx))
	require.Eventually(t, func() bool {
		var exists bool
		err := pg.Pool.QueryRow(context.Background(), "SELECT EXISTS(SELECT 1 FROM profiles.users WHERE id=$1::uuid)", user.ID).Scan(&exists)
		return err == nil && !exists
	}, 15*time.Second, 25*time.Millisecond)
	require.True(t, revoked(leftover), "purge left a live key with no creator")
	var live int
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT count(*) FROM profiles.api_keys WHERE created_by IS NULL AND revoked_at IS NULL`).Scan(&live))
	require.Zero(t, live)
}
