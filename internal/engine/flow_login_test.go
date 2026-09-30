package engine

import (
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// A password sign-in that checked the old password while a recovery was
// changing it mints no session: the session insert waits on the account's
// credential version and finds it changed.
func TestPasswordLoginRacingRecoveryMintsNoSession(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	f := newAccountFlow(t, pg.Pool, testConfig(), Deps{})
	ctx := t.Context()
	user := newUser(t, f.engine, "paused")
	lock, err := pg.Pool.Begin(ctx)
	require.NoError(t, err)
	defer lock.Rollback(ctx)
	_, err = lock.Exec(ctx, `SELECT id FROM users WHERE id=$1::uuid FOR UPDATE`, user.ID)
	require.NoError(t, err)
	changed := make(chan error, 1)
	go func() {
		changed <- f.engine.adminSetPassword(ctx, user.ID, "Replacement-password-12345")
	}()
	waitLocks := func(want int) {
		require.Eventually(t, func() bool {
			var n int
			err := pg.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%UserCredentialVersionForUpdate%'`).Scan(&n)
			return err == nil && n == want
		}, 5*time.Second, 10*time.Millisecond)
	}
	waitLocks(1)
	login := make(chan flowResponse, 1)
	go func() {
		login <- f.post("/password/login", map[string]any{"identifier": *user.Email, "password": testPassword})
	}()
	waitLocks(2)
	require.NoError(t, lock.Commit(ctx))
	require.NoError(t, <-changed)
	f.expect(401, <-login)
	var sessions int
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT count(*) FROM refresh_sessions WHERE user_id=$1::uuid`, user.ID).Scan(&sessions))
	require.Zero(t, sessions, "a password check preceding completed recovery cannot mint a session")
}
