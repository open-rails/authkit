package authkit_test

import (
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

func TestTenantAuthorityChangesSweepOnlyItsIssuedAppCredentials(t *testing.T) {
	roles := authkit.NewRoles()
	app := roles.Persona("app", authkit.APIKeys)
	read := app.Permission("content", "read")
	reader := app.Role("reader", read)
	shared, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.DefaultTenantID = iam.TenantID{}
		c.Roles = roles
		c.TwoFactor.Mode = iam.TwoFactorDisabled
	}))
	views := make([]*authkit.Client, 2)
	owners := make([]authtest.User, 2)
	groups := make([]iam.GroupRef, 2)
	keys := make([]iam.APIKeyCreated, 2)
	for i := range views {
		id := iam.NewTenantID()
		require.NoError(t, shared.CreateTenant(t.Context(), iam.Tenant{ID: id}))
		var err error
		views[i], err = shared.ForTenant(t.Context(), id)
		require.NoError(t, err)
		owners[i] = authtest.NewUser(t, views[i])
		authtest.GrantRole(t, views[i], iam.GroupByID(id.String()), iam.UserSubject(owners[i].ID), iam.TenantPersona().OwnerRole())
		group, err := views[i].CreateGroup(t.Context(), iam.NewGroup{Persona: app.Persona})
		require.NoError(t, err)
		groups[i] = iam.GroupByID(group.ID)
		keys[i], err = views[i].CreateAPIKey(t.Context(), iam.UserIdentity(owners[i].ID), groups[i], iam.NewAPIKey{Name: "tenant-issued", Role: reader})
		require.NoError(t, err)
		_, err = shared.ResolveAPIKey(t.Context(), keys[i].Secret)
		require.NoError(t, err)
	}
	// Ordinary profile maintenance must not revoke a key whose creator still
	// covers its app role through tenant authority.
	language := "en"
	_, err := views[0].UpdateUser(t.Context(), iam.SystemIdentity(), owners[0].ID, iam.UserUpdate{PreferredLanguage: &language})
	require.NoError(t, err)
	_, err = shared.ResolveAPIKey(t.Context(), keys[0].Secret)
	require.NoError(t, err, "unchanged inherited authority must survive a sweep")
	backup := authtest.NewUser(t, views[0])
	tenant := iam.GroupByID(owners[0].TenantID.String())
	authtest.GrantRole(t, views[0], tenant, iam.UserSubject(backup.ID), iam.TenantPersona().OwnerRole())
	require.NoError(t, views[0].RemoveGroupMember(t.Context(), iam.SystemIdentity(), tenant, iam.UserSubject(owners[0].ID)))
	_, err = shared.ResolveAPIKey(t.Context(), keys[0].Secret)
	require.NoError(t, err, "removing a creator's tenant role does not retire organization keys")
	_, err = shared.ResolveAPIKey(t.Context(), keys[1].Secret)
	require.NoError(t, err, "another tenant's key must survive")
	role, err := views[1].GroupRole(t.Context(), iam.GroupByID(owners[1].TenantID.String()), iam.TenantPersona().OwnerRole())
	require.NoError(t, err)
	require.Contains(t, role.Permissions, read)
	require.NotContains(t, role.Permissions, roles.Root.Users.Read)
}
