package engine

import (
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testoutbox"
	"github.com/stretchr/testify/require"
)

// A passwordless completion paused on the account lock must not delete a
// newer issuance: both the paused code and the newer one sign in.
func TestPasswordlessCompletionKeepsNewerIssuance(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.Registration.PasswordlessLogin = true
	f := newAccountFlow(t, pg.Pool, cfg)
	pool, ctx := fixtureBackend(f.service.Backend()).pg, t.Context()
	email := uniqueEmail("reissue")
	user, err := fixtureBackend(f.service.Backend()).createUser(ctx, email, "reissue"+uniqueSuffix())
	require.NoError(t, err)
	require.NoError(t, fixtureBackend(f.service.Backend()).markEmailVerified(ctx, user.ID))
	begin := func() {
		f.expect(202, f.post("/passwordless/start", map[string]any{"identifier": email, "mode": "both"}))
	}
	begin()
	old := sentCode(t, f.email, testoutbox.Verification)
	lock, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer lock.Rollback(ctx)
	_, err = lock.Exec(ctx, `SELECT id FROM users WHERE id=$1::uuid FOR UPDATE`, user.ID)
	require.NoError(t, err)
	completed := make(chan flowResponse, 1)
	go func() { completed <- f.post("/passwordless/confirm", map[string]any{"identifier": email, "code": old}) }()
	require.Eventually(t, func() bool {
		var n int
		err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%UserCredentialVersionForUpdate%'`).Scan(&n)
		return err == nil && n == 1
	}, 5*time.Second, 10*time.Millisecond)
	begin()
	newCode := sentCode(t, f.email, testoutbox.Verification)
	require.NoError(t, lock.Commit(ctx))
	f.expect(200, <-completed)
	f.expect(200, f.post("/passwordless/confirm", map[string]any{"identifier": email, "code": newCode}))
}
