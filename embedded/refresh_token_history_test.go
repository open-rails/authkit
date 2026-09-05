package embedded

import (
	"context"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/testdb"
	pgmigrations "github.com/open-rails/authkit/migrations/postgres"
	"github.com/stretchr/testify/require"
)

func TestRefreshTokenHistory_AtomicRotation(t *testing.T) {
	svc := keyedServiceWithPG(t)
	ctx := context.Background()
	uid := mkRefreshTestUser(t, ctx, svc, "history-atomic")
	sid, token, _, err := svc.IssueRefreshSession(ctx, uid, "test", nil)
	require.NoError(t, err)
	oldHash, newHash := svc.hashRefresh(token), svc.hashRefresh("successor")
	params := db.SessionRotateParams{ID: sid, ExpectedCurrentTokenHash: oldHash, NewTokenHash: newHash, PreviousSuccessorSealed: sealGraceSuccessor(token, "successor")}
	countHistory := func() int {
		var n int
		require.NoError(t, svc.pg.QueryRow(ctx, `SELECT count(*) FROM profiles.refresh_token_history WHERE session_id=$1::uuid`, sid).Scan(&n))
		return n
	}
	// A transaction rollback must undo both history and rotation.
	tx, err := svc.pg.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	rotated, err := db.New(tx).SessionRotate(ctx, params)
	require.NoError(t, err)
	require.EqualValues(t, 1, rotated)
	require.NoError(t, tx.Rollback(ctx))
	require.Zero(t, countHistory())
	_, err = svc.q.SessionByCurrentTokenHash(ctx, db.SessionByCurrentTokenHashParams{CurrentTokenHash: oldHash, Issuer: svc.cfg.Token.Issuer})
	require.NoError(t, err)

	// Force the history insert to fail: the CAS cannot commit without its record.
	_, err = svc.pg.Exec(ctx, `INSERT INTO profiles.refresh_token_history(token_hash,session_id) VALUES($1,$2::uuid)`, oldHash, sid)
	require.NoError(t, err)
	_, err = svc.q.SessionRotate(ctx, params)
	require.Error(t, err)
	_, err = svc.q.SessionByCurrentTokenHash(ctx, db.SessionByCurrentTokenHashParams{CurrentTokenHash: oldHash, Issuer: svc.cfg.Token.Issuer})
	require.NoError(t, err)
	_, err = svc.pg.Exec(ctx, `DELETE FROM profiles.refresh_token_history WHERE session_id=$1::uuid`, sid)
	require.NoError(t, err)

	// The successful CAS records exactly one hash; a loser records nothing.
	rotated, err = svc.q.SessionRotate(ctx, params)
	require.NoError(t, err)
	require.EqualValues(t, 1, rotated)
	rotated, err = svc.q.SessionRotate(ctx, params)
	require.NoError(t, err)
	require.Zero(t, rotated)
	require.Equal(t, 1, countHistory())
}

func TestRefreshTokenHistory_Cleanup(t *testing.T) {
	svc := keyedServiceWithPG(t)
	ctx := context.Background()
	uid := mkRefreshTestUser(t, ctx, svc, "history-cleanup")
	ids := make([]string, 3)
	// Issue finite, absolute lifetimes. Rotation must not extend any expiry.
	svc.cfg.Token.RefreshTokenDuration = time.Hour
	for i := range ids {
		sid, token, expiry, err := svc.IssueRefreshSession(ctx, uid, "test", nil)
		require.NoError(t, err)
		ids[i] = sid
		for range 2 {
			_, _, token, err = svc.ExchangeRefreshToken(ctx, token, "test", nil)
			require.NoError(t, err)
		}
		var stored time.Time
		require.NoError(t, svc.pg.QueryRow(ctx, `SELECT expires_at FROM profiles.refresh_sessions WHERE id=$1::uuid`, sid).Scan(&stored))
		require.WithinDuration(t, *expiry, stored, time.Microsecond)
	}
	require.NoError(t, svc.RevokeSessionByIDForUser(ctx, uid, ids[0]))
	_, err := svc.pg.Exec(ctx, `UPDATE profiles.refresh_sessions SET expires_at=now()-interval '1 second' WHERE id=$1::uuid`, ids[1])
	require.NoError(t, err)
	require.NoError(t, svc.CleanupExpiredAuthState(ctx))
	var retained []string
	rows, err := svc.pg.Query(ctx, `SELECT DISTINCT session_id::text FROM profiles.refresh_token_history WHERE session_id=ANY($1::uuid[])`, ids)
	require.NoError(t, err)
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		retained = append(retained, id)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	require.Equal(t, []string{ids[2]}, retained, "live family history must survive the cleanup")

	// Hard deletion cascades history, including for an indefinite session.
	svc.cfg.Token.RefreshTokenDuration = 0
	sid, token, _, err := svc.IssueRefreshSession(ctx, uid, "forever", nil)
	require.NoError(t, err)
	_, _, _, err = svc.ExchangeRefreshToken(ctx, token, "forever", nil)
	require.NoError(t, err)
	require.NoError(t, svc.CleanupExpiredAuthState(ctx))
	var n int
	require.NoError(t, svc.pg.QueryRow(ctx, `SELECT count(*) FROM profiles.refresh_token_history WHERE session_id=$1::uuid`, sid).Scan(&n))
	require.Equal(t, 1, n)
	_, err = svc.pg.Exec(ctx, `DELETE FROM profiles.refresh_sessions WHERE user_id=$1::uuid`, uid)
	require.NoError(t, err)
	require.NoError(t, svc.pg.QueryRow(ctx, `SELECT count(*) FROM profiles.refresh_token_history WHERE session_id=ANY($1::uuid[])`, append(ids, sid)).Scan(&n))
	require.Zero(t, n)
}

func TestRefreshTokenHistory_CutoverRevokesExistingSessions(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := context.Background()
	// Restore the prior session shape in this disposable, test-owned database.
	_, err := pg.Pool.Exec(ctx, `DROP TABLE profiles.refresh_token_history;
 ALTER TABLE profiles.refresh_sessions ADD COLUMN previous_token_hash bytea`)
	require.NoError(t, err)
	var uid, sid string
	require.NoError(t, pg.Pool.QueryRow(ctx, `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(&uid))
	require.NoError(t, pg.Pool.QueryRow(ctx, `INSERT INTO profiles.refresh_sessions(id,family_id,user_id,issuer,current_token_hash,previous_token_hash)
 VALUES(uuidv7(),uuidv7(),$1::uuid,'https://migration.example',$2,$3) RETURNING id::text`, uid, []byte("current"), []byte("previous")).Scan(&sid))
	migration, err := pgmigrations.FS.ReadFile("0012_refresh_token_history.up.sql")
	require.NoError(t, err)
	_, err = pg.Pool.Exec(ctx, string(migration))
	require.NoError(t, err)
	var revoked bool
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM profiles.refresh_sessions WHERE id=$1::uuid`, sid).Scan(&revoked))
	require.True(t, revoked, "incomplete pre-change histories require reauthentication")
	var oldColumn bool
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='profiles' AND table_name='refresh_sessions' AND column_name='previous_token_hash')`).Scan(&oldColumn))
	require.False(t, oldColumn)
}
