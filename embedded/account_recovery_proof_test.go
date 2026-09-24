package embedded

import (
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestRecoveryProofCannotCrossGenerationOrRaceFinalPurge(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := maintenanceConfig()
	cfg.TwoFactor.Mode = TwoFactorDisabled
	runtime, err := New(cfg, Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(runtime.Close)
	s := runtime.engine
	user, err := s.CreateUser(t.Context(), "recovery-race@example.test", "recoveryrace")
	require.NoError(t, err)
	require.NoError(t, s.MarkEmailVerified(t.Context(), user.ID))
	require.NoError(t, s.AdminSetPassword(t.Context(), user.ID, "Correct-race-password-1"))
	require.NoError(t, s.SoftDeleteUser(t.Context(), user.ID))
	deletedVersion, err := s.q.UserCredentialVersion(t.Context(), user.ID)
	require.NoError(t, err)
	_, err = s.verifyContactProof(t.Context(), user.ID, deletedVersion.CredentialVersion, PasswordlessChannelEmail, *user.Email, nil)
	require.ErrorIs(t, err, ErrUserBanned, "standalone contact finalization cannot use the recovery-only login allowance")
	var verified bool
	require.NoError(t, s.pg.QueryRow(t.Context(), "SELECT email_verified FROM users WHERE id=$1::uuid", user.ID).Scan(&verified))
	require.False(t, verified)
	first, err := s.PasswordLogin(t.Context(), PasswordLoginInput{Identifier: *user.Email, Password: "Correct-race-password-1"})
	require.NoError(t, err)
	require.Equal(t, LoginRecoveryRequired, first.Kind)
	token := first.Recovery.Token
	var saved accountRecoveryProof
	_, ok, err := s.ephemReadJSON(t.Context(), "account-recovery:"+sha256Hex(token), &saved)
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, s.ConfirmAccountRecovery(t.Context(), token))
	require.NoError(t, s.SoftDeleteUser(t.Context(), user.ID))
	version, err := s.q.UserCredentialVersion(t.Context(), user.ID)
	require.NoError(t, err)
	// Deliberately keep an old generation with a current CV in server-side test
	// state, so the generation fence is tested independently of the CV fence.
	saved.Version = version.CredentialVersion
	key := "account-recovery:" + sha256Hex(token)
	require.NoError(t, s.ephemSetJSON(t.Context(), key, saved, time.Minute))
	require.Error(t, s.ConfirmAccountRecovery(t.Context(), token))

	current, err := s.PasswordLogin(t.Context(), PasswordLoginInput{Identifier: *user.Email, Password: "Correct-race-password-1"})
	require.NoError(t, err)
	token = current.Recovery.Token
	key = "account-recovery:" + sha256Hex(token)
	_, ok, err = s.ephemReadJSON(t.Context(), key, &saved)
	require.NoError(t, err)
	require.True(t, ok)
	expired := saved
	expired.ExpiresAt = time.Now().Add(-time.Second)
	require.NoError(t, s.ephemSetJSON(t.Context(), key, expired, time.Minute))
	require.Error(t, s.ConfirmAccountRecovery(t.Context(), token), "stored confirmation expiry is enforced independently of store TTL")
	rows, err := s.pg.Query(t.Context(), "SELECT id FROM account_deletion_deliveries ORDER BY id")
	require.NoError(t, err)
	deliveries, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	require.NoError(t, err)
	for _, id := range deliveries {
		require.NoError(t, s.deliverAccountEvent(t.Context(), id))
	}
	generation := prepareExpiredDeletion(t, s, user.ID)
	require.Equal(t, generation, saved.Generation)
	version, err = s.q.UserCredentialVersion(t.Context(), user.ID)
	require.NoError(t, err)
	// Even a server-side grant with an artificially extended expiry/current CV
	// cannot override the durable deletion deadline/finalizing state.
	saved.Version = version.CredentialVersion
	saved.ExpiresAt = time.Now().Add(time.Minute)
	require.NoError(t, s.ephemSetJSON(t.Context(), key, saved, time.Minute))
	start := make(chan struct{})
	var wg sync.WaitGroup
	var restoreErr, purgeErr error
	wg.Go(func() { <-start; restoreErr = s.ConfirmAccountRecovery(t.Context(), token) })
	wg.Go(func() { <-start; purgeErr = s.finalizeAccountDeletion(t.Context(), generation, true) })
	close(start)
	wg.Wait()
	require.Error(t, restoreErr)
	require.NoError(t, purgeErr)
	var exists bool
	require.NoError(t, s.pg.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1::uuid)`, user.ID).Scan(&exists))
	require.False(t, exists)
	var state string
	require.NoError(t, s.pg.QueryRow(t.Context(), `SELECT state FROM account_deletions WHERE id=$1::uuid`, generation).Scan(&state))
	require.Equal(t, "purged", state)
}
