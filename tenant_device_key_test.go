package authkit_test

import (
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/devicekey"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

func TestTenantDeviceProofCannotTouchAnotherDirectory(t *testing.T) {
	shared, outbox := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.DefaultTenantID = iam.TenantID{}
		c.DeviceKeys.Enabled = true
		c.TwoFactor.Mode = iam.TwoFactorDisabled
	}))
	views := make([]*authkit.Client, 2)
	clients := make([]*devicekey.Client, 2)
	for i := range views {
		id := iam.NewTenantID()
		require.NoError(t, shared.CreateTenant(t.Context(), iam.Tenant{ID: id}))
		var err error
		views[i], err = shared.ForTenant(t.Context(), id)
		require.NoError(t, err)
		server := httptest.NewServer(views[i].Handler())
		t.Cleanup(server.Close)
		clients[i], err = devicekey.NewClient(server.URL+views[i].APIBase(), server.Client())
		require.NoError(t, err)
	}
	user := authtest.NewUser(t, views[1])
	key := authtest.EnrollDeviceKey(t, views[1], outbox, user)
	before, err := views[1].DeviceKeys(t.Context(), user.ID)
	require.NoError(t, err)
	require.Len(t, before, 1)
	_, err = clients[0].Login(t.Context(), key.ID, key.Key)
	require.Error(t, err)
	after, err := views[1].DeviceKeys(t.Context(), user.ID)
	require.NoError(t, err)
	require.Equal(t, before[0].LastUsedAt, after[0].LastUsedAt, "a foreign-directory attempt must not touch the key")
	session, err := clients[1].Login(t.Context(), key.ID, key.Key)
	require.NoError(t, err)
	require.NotEmpty(t, session.AccessToken)
}
