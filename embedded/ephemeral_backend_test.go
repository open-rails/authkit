package embedded

import (
	"testing"

	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// #305: the per-process memory ephemeral store is refused outside a dev-like
// Environment unless Ephemeral.AllowMemory opts in; Redis always passes.
func TestNewRefusesMemoryEphemeralOutsideDev(t *testing.T) {
	pool := newGenesisTestPool(t)
	base := Config{
		Keys:         testKeys(t),
		Token:        TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"test-app"}, ExpectedAudiences: []string{"test-app"}},
		Registration: RegistrationConfig{Verification: RegistrationVerificationNone},
	}

	dev := base
	dev.Environment = "dev"
	c, err := New(dev, pool)
	require.NoError(t, err)
	require.Equal(t, "memory", Unwrap(c).EphemeralBackend())

	for _, env := range []string{"production", "staging"} {
		prod := base
		prod.Environment = env
		_, err := New(prod, pool)
		require.Error(t, err, "%s without Redis must refuse", env)
		require.Contains(t, err.Error(), "Ephemeral.AllowMemory")

		allowed := prod
		allowed.Ephemeral = EphemeralConfig{AllowMemory: true}
		c, err := New(allowed, pool)
		require.NoError(t, err, "%s with Ephemeral.AllowMemory must construct", env)
		require.Equal(t, "memory", Unwrap(c).EphemeralBackend())

		rdb := testdb.ScratchRedis(t)
		c, err = New(prod, pool, WithRedis(rdb))
		require.NoError(t, err, "%s with Redis must construct", env)
		require.Equal(t, "redis", Unwrap(c).EphemeralBackend())
	}
}
