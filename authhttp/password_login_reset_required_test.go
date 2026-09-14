package authhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	svc, err := newServer(newServerClient(t, cfg, pool))
	require.NoError(t, err)

	coreSvc := svc.svc
	email, username := uniqueEmail("legacy-reset-required"), "resetrequired"+uniqueSuffix()
	u, err := coreSvc.CreateUser(ctx, email, username)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1`, u.ID) })
	require.NoError(t, coreSvc.UpsertPasswordHash(ctx, u.ID, "reset-required", embedded.HashAlgoLegacyResetRequired, nil))
	good, err := password.HashArgon2id("Known-password-123")
	require.NoError(t, err)
	for _, stored := range []struct {
		hash, algo string
		reset      bool
	}{
		{"legacy", embedded.HashAlgoLegacyResetRequired, true},
		{"$argon2id$v=19$m=4294967295,t=1,p=1$c2FsdA$aGFzaA", "argon2id", true},
		{"legacy-unknown-format", "unknown", true},
		{good, "argon2id", false},
	} {
		// Simulate rows written before validation existed, without calling a KDF
		// on the rejected work factor.
		_, err := pool.Exec(ctx, `UPDATE profiles.user_passwords SET password_hash=$2, hash_algo=$3 WHERE user_id=$1`, u.ID, stored.hash, stored.algo)
		require.NoError(t, err)
		for _, identifier := range []string{email, username} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/password/login", strings.NewReader(`{"identifier":"`+identifier+`","password":"whatever"}`))
			r.Header.Set("Content-Type", "application/json")
			svc.apiHandler().ServeHTTP(w, r)
			require.Equal(t, http.StatusUnauthorized, w.Code)
			require.Equal(t, stored.reset, strings.Contains(w.Body.String(), `"password_reset_required"`), w.Body.String())
		}
	}
}
