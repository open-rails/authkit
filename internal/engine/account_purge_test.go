package engine

import (
	"context"
	"testing"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// TestAccountPurgeSweepsCredentialsBeforeTheRowGoes (H1): PurgeUsers is the
// system's; it closes the recovery window at once, and once the row goes no
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
	require.NoError(t, runtime.withAuthorityMutation(ctx, iam.SystemActor(), func(st *permissionGroupStore) error {
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
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority, "purge is the system's")
	require.NoError(t, itemErr(runtime.PurgeUsers(ctx, iam.SystemActor(), []string{user.ID})))
	require.True(t, revoked(issued), "the soft delete sweeps the account's keys")
	restore, err := runtime.RestoreUsers(ctx, iam.SystemActor(), []string{user.ID})
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

// TestAccountPurgeKeepsTheRealDeletionTime: a purge ends the recovery window
// by moving purge_at forward, never by backdating deleted_at, whether the
// account was live or deleted earlier.
func TestAccountPurgeKeepsTheRealDeletionTime(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	require.NoError(t, Migrate(t.Context(), pg.Pool, MigrateOptions{}))
	runtime, err := New(context.Background(), maintenanceConfig(), Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(runtime.Close)
	ctx := t.Context()
	op := iam.SystemActor()
	times := func(userID string) (users, deletion, purge time.Time) {
		t.Helper()
		require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT u.deleted_at, d.deleted_at, d.purge_at
 FROM profiles.users u JOIN profiles.account_deletions d ON d.user_id=u.id WHERE u.id=$1::uuid`, userID).Scan(&users, &deletion, &purge))
		return users, deletion, purge
	}

	earlier, err := runtime.createUser(ctx, "earlier@example.test", "earlieruser")
	require.NoError(t, err)
	require.NoError(t, itemErr(runtime.DeleteUsers(ctx, op, []string{earlier.ID})))
	deletedAt, _, windowEnd := times(earlier.ID)
	require.True(t, windowEnd.Equal(deletedAt.Add(720*time.Hour)))
	require.NoError(t, itemErr(runtime.PurgeUsers(ctx, op, []string{earlier.ID})))
	users, deletion, purge := times(earlier.ID)
	require.True(t, users.Equal(deletedAt) && deletion.Equal(deletedAt), "deleted_at keeps the soft-delete time")
	require.True(t, purge.Before(windowEnd) && !purge.Before(deletedAt), "purge_at moves to the purge")

	live, err := runtime.createUser(ctx, "live@example.test", "liveuser")
	require.NoError(t, err)
	before := time.Now()
	require.NoError(t, itemErr(runtime.PurgeUsers(ctx, op, []string{live.ID})))
	users, deletion, purge = times(live.ID)
	require.True(t, users.Equal(deletion))
	require.WithinDuration(t, before, deletion, time.Minute, "a purged live account is deleted now")
	require.False(t, purge.Before(deletion))
	for _, id := range []string{earlier.ID, live.ID} {
		res, err := runtime.RestoreUsers(ctx, op, []string{id})
		require.NoError(t, err)
		require.ErrorIs(t, res[0].Err, errmodel.E(errmodel.CodeAccountRecoveryExpired))
	}
}
