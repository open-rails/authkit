package engine

import (
	"context"
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// A provider sign-in's derived username fits the configured policy, and a
// taken one is suffixed within its maximum. The import ceiling and the
// invalid policy are in apitest's TestAccountPolicies.
func TestConfiguredUsernamePolicyGovernsDerivedNames(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := maintenanceConfig()
	cfg.Username = iam.UsernamePolicy{MinLength: 8, MaxLength: 10}
	rt, err := New(context.Background(), cfg, Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(rt.Close)

	first := rt.deriveUsernameForOAuth(t.Context(), "google", "", "ab@example.test", "")
	require.Equal(t, "ab_user_us", first)
	_, err = rt.createUser(t.Context(), "first@example.test", first)
	require.NoError(t, err)
	second := rt.deriveUsernameForOAuth(t.Context(), "google", "", "ab@example.test", "")
	require.Equal(t, "ab_user_u1", second, "a taken name is suffixed within the maximum")
	require.NoError(t, rt.ValidateUsername(second))
}
