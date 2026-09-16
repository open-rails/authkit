package authhttp

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/password"
)

// One HTTP workflow covers explicit migration markers, unsafe older rows and
// unsupported formats. A wrong password against a valid hash stays a normal
// authentication failure rather than requesting recovery.
func TestPasswordLogin_LegacyResetRequired(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)
	cfg := embedded.Config{
		Keys: testKeys(),
		Token: embedded.TokenConfig{
			Issuer:            "https://example.com",
			IssuedAudiences:   []string{"test-app"},
			ExpectedAudiences: []string{"test-app"},
		},
		Frontend:     embedded.FrontendConfig{BaseURL: "https://example.com"},
		Registration: embedded.RegistrationConfig{Verification: embedded.RegistrationVerificationNone},
	}
	sender := &captureEmailSender{}
	svc, err := newServer(newServerClient(t, cfg, pool, withEmailSender(sender)))
	require.NoError(t, err)

	coreSvc := svc.svc
	email, username := uniqueEmail("legacy-reset-required"), "resetrequired"+uniqueSuffix()
	u, err := coreSvc.CreateUser(ctx, email, username)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1`, u.ID) })
	require.NoError(t, coreSvc.UpsertPasswordHash(ctx, u.ID, "reset-required", embedded.HashAlgoLegacyResetRequired))
	good, err := password.HashArgon2id("Known-password-123")
	require.NoError(t, err)
	for _, stored := range []struct {
		hash, algo string
		reset      bool
	}{
		{"legacy", embedded.HashAlgoLegacyResetRequired, true},
		{"$argon2id$v=19$m=8,t=0,p=1$c2FsdA$aGFzaA", "argon2id", true},
		{"legacy-unknown-format", "unknown", true},
		{good, "argon2id", false},
	} {
		// Simulate rows written before validation existed, without calling a KDF
		// on the rejected work factor.
		_, err := pool.Exec(ctx, `UPDATE profiles.user_passwords SET password_hash=$2, hash_algo=$3 WHERE user_id=$1`, u.ID, stored.hash, stored.algo)
		require.NoError(t, err)
		for _, identifier := range []string{email, username} {
			w := serveJSON(svc, http.MethodPost, "/password/login", `{"identifier":"`+identifier+`","password":"whatever"}`)
			require.Equal(t, http.StatusUnauthorized, w.Code)
			require.Equal(t, stored.reset, strings.Contains(w.Body.String(), `"password_reset_required"`), w.Body.String())
		}
		if stored.reset {
			require.ErrorIs(t, coreSvc.CheckUserPassword(ctx, u.ID, "whatever"), embedded.ErrPasswordResetRequired)
			require.ErrorIs(t, coreSvc.ChangePassword(ctx, u.ID, "whatever", "Replacement-password-12345", nil), embedded.ErrPasswordResetRequired)
		}
	}
	// Recover through the public reset operation, including the delivery token;
	// a direct hash upsert would not prove that recovery clears the condition.
	require.NoError(t, coreSvc.UpsertPasswordHash(ctx, u.ID, "reset-required", embedded.HashAlgoLegacyResetRequired))
	w := serveJSON(svc, http.MethodPost, "/password/reset/request", `{"identifier":"`+email+`"}`)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	w = serveJSON(svc, http.MethodPost, "/password/reset/confirm", `{"token":"`+sender.passwordResetToken(t)+`","new_password":"Recovered-password-12345"}`)
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	w = serveJSON(svc, http.MethodPost, "/password/login", `{"identifier":"`+email+`","password":"Recovered-password-12345"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	requireTokenResponse(t, w)
	require.NoError(t, coreSvc.CheckUserPassword(ctx, u.ID, "Recovered-password-12345"))
}
