package authkit_test

import (
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

func TestTenantNativeAccountBoundaries(t *testing.T) {
	shared, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.DefaultTenantID = iam.TenantID{}
	}))
	views := make([]*authkit.Client, 2)
	users := make([]authtest.User, 2)
	for i := range views {
		tenant := iam.NewTenantID()
		require.NoError(t, shared.CreateTenant(t.Context(), iam.Tenant{ID: tenant}))
		var err error
		views[i], err = shared.ForTenant(t.Context(), tenant)
		require.NoError(t, err)
		users[i] = authtest.NewUser(t, views[i])
	}
	a, b := views[0], views[1]
	foreign := users[1]
	tokens := authtest.SignIn(t, b, foreign)
	claims, err := b.Verify(t.Context(), tokens.AccessToken)
	require.NoError(t, err)
	before, err := b.User(t.Context(), iam.UserByID(foreign.ID))
	require.NoError(t, err)

	t.Run("bulk directory", func(t *testing.T) {
		ids := []string{users[0].ID, foreign.ID}
		private, err := a.Users(t.Context(), ids)
		require.NoError(t, err)
		require.Contains(t, private, users[0].ID)
		require.NotContains(t, private, foreign.ID)
		public, err := a.PublicUsers(t.Context(), ids)
		require.NoError(t, err)
		require.Contains(t, public, users[0].ID)
		require.NotContains(t, public, foreign.ID)
	})
	newName := "wrongtenantname"
	for _, test := range []struct {
		name string
		run  func() error
	}{
		{"mint token", func() error {
			token, err := a.MintAccessToken(t.Context(), foreign.ID, iam.AccessTokenOptions{})
			require.Empty(t, token.Value)
			return err
		}},
		{"update user", func() error {
			_, err := a.UpdateUser(t.Context(), iam.SystemIdentity(), foreign.ID, iam.UserUpdate{Username: &newName})
			return err
		}},
		{"public metadata", func() error {
			return a.PatchPublicMetadata(t.Context(), iam.SystemIdentity(), foreign.ID, map[string]any{"wrong_tenant": true})
		}},
		{"ban", func() error {
			return a.Ban(t.Context(), iam.SystemIdentity(), foreign.ID, iam.Ban{Reason: "wrong tenant"})
		}},
		{"unban", func() error { return a.Unban(t.Context(), iam.SystemIdentity(), foreign.ID) }},
		{"reset MFA", func() error { return a.ResetAccountMFA(t.Context(), foreign.ID) }},
		{"revoke sessions", func() error {
			_, err := a.RevokeAccountSessions(t.Context(), iam.SystemIdentity(), foreign.ID)
			return err
		}},
		{"link provider", func() error {
			return a.LinkProvider(t.Context(), foreign.ID, iam.ProviderLink{Issuer: "https://idp.example.test", Subject: "foreign"})
		}},
	} {
		t.Run(test.name, func(t *testing.T) { require.ErrorIs(t, test.run(), iam.ErrUserNotFound) })
	}
	for _, test := range []struct {
		name string
		run  func() ([]iam.OpResult, error)
	}{
		{"delete", func() ([]iam.OpResult, error) {
			return a.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{foreign.ID})
		}},
		{"restore", func() ([]iam.OpResult, error) {
			return a.RestoreUsers(t.Context(), iam.SystemIdentity(), []string{foreign.ID})
		}},
		{"purge", func() ([]iam.OpResult, error) { return a.PurgeUsers(t.Context(), []string{foreign.ID}) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			results, err := test.run()
			require.NoError(t, err)
			require.Len(t, results, 1)
			require.Equal(t, foreign.ID, results[0].ID)
			require.ErrorIs(t, results[0].Err, iam.ErrUserNotFound)
		})
	}

	// Refused foreign operations must leave the owning tenant's account and
	// existing session intact, including its credential version.
	after, err := b.User(t.Context(), iam.UserByID(foreign.ID))
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.NoError(t, b.CheckSession(t.Context(), claims))
	authtest.SignIn(t, b, foreign)
}
