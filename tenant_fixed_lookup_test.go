package authkit_test

import (
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/tenancy"
	"github.com/stretchr/testify/require"
)

func TestTenantFixedUserInfoIgnoresAnotherOperationContext(t *testing.T) {
	authority, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.DefaultTenantID = iam.TenantID{} }))
	ids := []iam.TenantID{iam.NewTenantID(), iam.NewTenantID()}
	clients := make([]*authkit.Client, 2)
	users := make([]authtest.User, 2)
	for i, id := range ids {
		require.NoError(t, authority.CreateTenant(t.Context(), iam.Tenant{ID: id}))
		var err error
		clients[i], err = authority.ForTenant(t.Context(), id)
		require.NoError(t, err)
		users[i] = authtest.NewUser(t, clients[i])
	}
	contextB := tenancy.With(t.Context(), ids[1])
	found, err := clients[0].UserInfo().Get(contextB, []string{users[0].ID, users[1].ID})
	require.NoError(t, err)
	require.Contains(t, found, users[0].ID)
	require.NotContains(t, found, users[1].ID)
	dynamic, err := authority.UserInfo().Get(contextB, []string{users[0].ID, users[1].ID})
	require.NoError(t, err)
	require.NotContains(t, dynamic, users[0].ID)
	require.Contains(t, dynamic, users[1].ID)
}
