package authkit_test

import (
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

func TestTenantDeviceKeyRegistrationKeepsSameEmailSeparate(t *testing.T) {
	shared, outbox := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.DefaultTenantID = iam.TenantID{}; c.DeviceKeys.Enabled = true }))
	owners := []iam.TenantID{iam.NewTenantID(), iam.NewTenantID()}
	ids := make([]string, 2)
	for i, owner := range owners {
		require.NoError(t, shared.CreateTenant(t.Context(), iam.Tenant{ID: owner}))
		view, err := shared.ForTenant(t.Context(), owner)
		require.NoError(t, err)
		// Enrollment is itself the mailbox-proven registration, with no existing
		// native account for this email in either independent directory.
		key := authtest.EnrollDeviceKey(t, view, outbox, authtest.User{Email: "new-device@example.test"})
		user, err := view.User(t.Context(), iam.UserByEmail("new-device@example.test"))
		require.NoError(t, err)
		require.Equal(t, owner, user.TenantID)
		require.True(t, user.EmailVerified)
		claims, err := shared.Verify(t.Context(), key.AccessToken)
		require.NoError(t, err)
		require.Equal(t, owner.String(), claims.TenantID)
		require.Equal(t, user.ID, claims.UserID)
		ids[i] = user.ID
	}
	require.NotEqual(t, ids[0], ids[1], "proving one shared mailbox creates no cross-tenant account merge")
}
