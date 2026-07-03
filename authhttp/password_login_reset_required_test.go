package authhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
)

// TestPasswordLogin_LegacyResetRequired drives the full HTTP handler against a
// real database: a user whose stored hash is flagged
// embedded.HashAlgoLegacyResetRequired must get 401 with the machine-readable code
// "password_reset_required" (same status family as invalid_credentials; only
// the body code differs, and only for this flagged cohort). Skips when
// AUTHKIT_TEST_DATABASE_URL is unset.
func TestPasswordLogin_LegacyResetRequired(t *testing.T) {
	dsn := os.Getenv("AUTHKIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTHKIT_TEST_DATABASE_URL not set; skipping DB-backed test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	cfg := embedded.Config{
		Keys: embedded.KeysConfig{AllowEphemeralDevKeys: true}, // #231: tests opt in explicitly
		Token: embedded.TokenConfig{
			Issuer:            "https://example.com",
			IssuedAudiences:   []string{"test-app"},
			ExpectedAudiences: []string{"test-app"},
		},
		Frontend:     embedded.FrontendConfig{BaseURL: "https://example.com"},
		Registration: embedded.RegistrationConfig{Verification: embedded.RegistrationVerificationNone},
	}
	svc, err := NewServer(newServerClient(t, cfg, pool))
	require.NoError(t, err)

	coreSvc := authcore.NewService(embedded.Config{Token: embedded.TokenConfig{Issuer: "https://example.com"}}, authcore.Keyset{}, embedded.WithPostgres(pool))
	const email = "legacy-reset-required-http@example.com"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE email=$1`, email)
	u, err := coreSvc.CreateUser(ctx, email, "legacyresetrequiredhttp")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, u.ID) })
	require.NoError(t, coreSvc.UpsertPasswordHash(ctx, u.ID, "8RmkP1jcmYBbE", embedded.HashAlgoLegacyResetRequired, nil))

	for _, identifier := range []string{email, "legacyresetrequiredhttp"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/password/login", strings.NewReader(`{"login":"`+identifier+`","password":"whatever"}`))
		r.Header.Set("Content-Type", "application/json")
		svc.APIHandler().ServeHTTP(w, r)
		require.Equal(t, http.StatusUnauthorized, w.Code, "identifier %q", identifier)
		require.Contains(t, w.Body.String(), `"password_reset_required"`, "identifier %q", identifier)
	}
}
