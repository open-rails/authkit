package engine

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// A database failure cannot masquerade as a revoked refresh credential: the
// very same credential must work again once the dependency is available.
func TestRefreshDatabaseFailureDoesNotRejectCredential(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	f := newAccountFlow(t, pg.Pool, testConfig(), config.Deps{})
	user := newUser(t, f.engine, "refresh-outage")
	login := f.expect(http.StatusOK, f.post("/password/login", map[string]any{"identifier": *user.Email, "password": testPassword}))
	refresh := map[string]any{"grant_type": "refresh_token", "refresh_token": login.tokens().RefreshToken}

	_, err := pg.Pool.Exec(t.Context(), `ALTER TABLE refresh_sessions RENAME TO refresh_sessions_unavailable`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pg.Pool.Exec(context.Background(), `ALTER TABLE IF EXISTS refresh_sessions_unavailable RENAME TO refresh_sessions`)
	})
	failed := f.expect(http.StatusInternalServerError, f.post("/token", refresh))
	require.Equal(t, "internal_error", failed.Error.Code)
	for _, cookie := range failed.cookies {
		require.False(t, strings.Contains(cookie.Name, "authkit_rt"), "refresh cookie changed on outage")
	}
	require.NotContains(t, failed.raw, *login.tokens().RefreshToken)

	_, err = pg.Pool.Exec(t.Context(), `ALTER TABLE refresh_sessions_unavailable RENAME TO refresh_sessions`)
	require.NoError(t, err)
	restored := f.expect(http.StatusOK, f.post("/token", refresh))
	require.NotEmpty(t, restored.tokens().AccessToken)
	claims, err := f.engine.Verify(t.Context(), restored.tokens().AccessToken)
	require.NoError(t, err)
	require.Equal(t, user.ID, claims.UserID)
	require.NoError(t, f.engine.RevokeIssuerSessions(t.Context(), user.ID, nil))
	revoked := f.expect(http.StatusUnauthorized, f.post("/token", map[string]any{"grant_type": "refresh_token", "refresh_token": restored.tokens().RefreshToken}))
	require.Equal(t, "invalid_token", revoked.Error.Code)
}

// Revoke-all sees the session a refresh-derived MFA completion commits, even
// when revocation began while that completion held the source session.
func TestRevokeAllCoversRefreshDerivedMFASession(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	f := newAccountFlow(t, pg.Pool, testConfig(), config.Deps{})
	ctx := t.Context()
	user := newUser(t, f.engine, "revall")
	initial := f.expect(200, f.post("/password/login", map[string]any{"identifier": *user.Email, "password": testPassword}))
	_, err := f.engine.enableFactor(ctx, user.ID, "email", nil, authflow.AllowAdditionalFactors)
	require.NoError(t, err)
	needed := f.expect(200, f.post("/token", map[string]any{"grant_type": "refresh_token", "refresh_token": initial.tokens().RefreshToken}))
	completion := map[string]any{"user_id": user.ID, "challenge": needed.challenge(t), "code": sentCode(t, f.email, iam.MessageLoginCode)}
	completed := f.completeWhileRevoking(user.ID, func() flowResponse { return f.post("/2fa/verify", completion) }, func(ctx context.Context) error {
		return f.engine.RevokeIssuerSessions(ctx, user.ID, nil)
	})
	f.expect(200, completed)
	var live int
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT count(*) FROM refresh_sessions WHERE user_id=$1::uuid AND revoked_at IS NULL`, user.ID).Scan(&live))
	require.Zero(t, live, "revoke-all cannot miss the derived session")
}
