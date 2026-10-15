package authkit_test

import (
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/stretchr/testify/require"
)

func TestTenantLegacyTokenUsesOnlyExplicitDefaultOwner(t *testing.T) {
	owner, other := iam.NewTenantID(), iam.NewTenantID()
	shared, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.DefaultTenantID = owner }), authtest.WithDeps(func(d *authkit.Deps) { d.KeySource = testKeys() }))
	require.NoError(t, shared.CreateTenant(t.Context(), iam.Tenant{ID: other}))
	second, err := shared.ForTenant(t.Context(), other)
	require.NoError(t, err)
	views := []*authkit.Client{shared, second}
	for i, view := range views {
		user := authtest.NewUser(t, view)
		token := authtest.SignIn(t, view, user).AccessToken
		typ, claims, ok := jose.Unverified(token)
		require.True(t, ok)
		delete(claims, "tenant_id")
		legacy, err := jose.Sign(t.Context(), testKeys().ActiveSigner(), typ, claims)
		require.NoError(t, err)
		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+legacy)
		verified, err := view.Authenticator().Authenticate(req)
		if i == 1 {
			require.Error(t, err, "a target view cannot redefine the legacy source owner")
			continue
		}
		require.NoError(t, err)
		require.Equal(t, owner.String(), verified.Identity().TenantID)
		actor, err := shared.ResolveTenantActor(t.Context(), verified)
		require.NoError(t, err)
		require.Equal(t, iam.TenantActor{AccountID: user.ID, TenantID: owner}, actor)
		claims["tenant_id"] = other.String()
		wrong, err := jose.Sign(t.Context(), testKeys().ActiveSigner(), typ, claims)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+wrong)
		_, err = shared.Authenticator().Authenticate(req)
		require.Error(t, err, "signed ownership must still match the live account")
	}
}
