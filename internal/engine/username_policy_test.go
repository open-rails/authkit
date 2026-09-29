package engine

import (
	"context"
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestConfiguredUsernamePolicyGovernsDerivedAndImportedNames(t *testing.T) {
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

	_, err = rt.createUser(t.Context(), "short@example.test", "shorty")
	e, ok := iam.AsError(err)
	require.True(t, ok, "%v", err)
	require.Equal(t, "username_too_short", e.Code())
	require.Equal(t, map[string]any{"min_length": 8, "max_length": 64}, e.Metadata(), "imports keep the 64-character import ceiling")

	cfg.Username = iam.UsernamePolicy{MinLength: 9, MaxLength: 8}
	_, err = New(context.Background(), cfg, Deps{Postgres: pg.Pool})
	require.ErrorContains(t, err, "invalid username policy")
}
