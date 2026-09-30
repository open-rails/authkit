package engine

import (
	"context"
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

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
	needed := f.expect(403, f.post("/token", map[string]any{"grant_type": "refresh_token", "refresh_token": initial.RefreshToken}))
	require.Equal(t, "2fa_required", needed.Error.Code)
	completion := map[string]any{"user_id": user.ID, "challenge": needed.Error.Metadata.Challenge, "code": sentCode(t, f.email, iam.MessageLoginCode)}
	completed := f.completeWhileRevoking(user.ID, func() flowResponse { return f.post("/2fa/verify", completion) }, func(ctx context.Context) error {
		return f.engine.RevokeIssuerSessions(ctx, user.ID, nil)
	})
	f.expect(200, completed)
	var live int
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT count(*) FROM refresh_sessions WHERE user_id=$1::uuid AND revoked_at IS NULL`, user.ID).Scan(&live))
	require.Zero(t, live, "revoke-all cannot miss the derived session")
}
