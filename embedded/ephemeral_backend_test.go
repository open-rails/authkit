package embedded

import (
	"testing"

	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// #305/#314: the per-process memory ephemeral store is refused unless
// Ephemeral.AllowMemory opts in; Redis always passes.
func TestNewRefusesMemoryEphemeralWithoutOptIn(t *testing.T) {
	pool := testdb.UnlockedPool(t)
	base := Config{
		Keys:         testKeys(t),
		Token:        TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"test-app"}, ExpectedAudiences: []string{"test-app"}},
		Registration: RegistrationConfig{Verification: RegistrationVerificationNone},
	}

	_, err := New(base, pool)
	require.Error(t, err, "no Redis and no opt-in must refuse")
	require.Contains(t, err.Error(), "Ephemeral.AllowMemory")

	allowed := base
	allowed.Ephemeral = EphemeralConfig{AllowMemory: true}
	c, err := New(allowed, pool)
	require.NoError(t, err)
	require.Equal(t, "memory", Unwrap(c).EphemeralBackend())

	rdb := testdb.ScratchRedis(t)
	c, err = New(base, pool, WithRedis(rdb))
	require.NoError(t, err)
	require.Equal(t, "redis", Unwrap(c).EphemeralBackend())
}
