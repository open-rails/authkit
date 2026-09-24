package securitytest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSecurityPurgedUsernameStaysReserved: purging an account frees its row,
// never its username, so nobody can re-register the name and impersonate the
// purged user to people and links that still know it.
func TestSecurityPurgedUsernameStaysReserved(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits))
	ctx := context.Background()
	gone := h.newAccount("purged")
	// Final purge is this physical delete, after recovery and host callbacks.
	_, err := h.pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, gone.id)
	require.NoError(t, err)
	_, err = h.client.CreateUser(ctx, unique("impostor")+"@security.test", gone.username)
	require.Error(t, err, "the purged username was released for re-registration")
	_, err = h.client.GetUserByUsername(ctx, gone.username)
	require.Error(t, err, "the reserved name resolved to a dead account")
	t.Run("control: other names remain available", func(t *testing.T) {
		name := unique("fresh")
		_, err := h.client.CreateUser(ctx, name+"@security.test", name)
		require.NoError(t, err)
	})
}
