package engine

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// A password change against a legacy reset-required hash answers the
// catalog's 401 password_reset_required from a fresh session too (it was a
// call-site 400 before status came only from the catalog).
func TestPasswordChangeOnLegacyHashRequiresReset(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.TwoFactor.Mode = iam.TwoFactorDisabled
	f := newAccountFlow(t, pg.Pool, cfg)

	const email, pass = "legacy@example.test", "Correct-horse-battery-7"
	tokens := f.expect(http.StatusAccepted, f.post("/register", map[string]any{"identifier": email, "username": "legacyuser", "password": pass})).Tokens
	require.NotEmpty(t, tokens.AccessToken)
	_, err := pg.Pool.Exec(t.Context(), `UPDATE user_passwords p SET hash_algo=$1 FROM users u WHERE u.id=p.user_id AND u.email=$2`, iam.HashAlgoLegacyResetRequired, email)
	require.NoError(t, err)

	r := f.expect(http.StatusUnauthorized, f.request(http.MethodPost, "/user/password", tokens.AccessToken, map[string]any{"current_password": pass, "new_password": "Another-horse-battery-8"}))
	var env iam.ErrorEnvelope
	require.NoError(t, json.Unmarshal([]byte(r.raw), &env))
	require.Equal(t, "password_reset_required", env.Error.Code)
}
