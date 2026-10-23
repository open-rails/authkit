package authkit_test

import (
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

// The host supplies concrete content grants, not an admin-role exception in
// authorization. The same native walk must serve checks and effective grants.
func TestExplicitContentAdminInheritance(t *testing.T) {
	roles := authkit.NewRoles(authkit.APIKeys)
	app := roles.Persona("app", authkit.APIKeys, authkit.RemoteApplications)
	console := app.Permission("admin-console", "access")
	write := app.Permission("content", "write")
	moderate := app.Permission("comments", "moderate")
	app.RequireMFA(console)
	bundle := []iam.Grant{console, write, moderate}
	rootAdmin := roles.Root.Role("admin", bundle...)
	tenantAdmin := roles.Tenant.Role("admin", bundle...)
	appAdmin := app.Role("admin", bundle...)
	publisher := app.Role("publisher", write)
	issuer := roles.Root.Role("publisher-issuer", app.Credentials.Manage, write)
	billingWrite := roles.Root.Permission("billing", "write")
	client, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Roles, c.DefaultTenantID = roles, iam.TenantID{}
	}))
	ctx := t.Context()
	var tenants []*authkit.Client
	var tenantGroups, apps []iam.GroupRef
	for range 2 {
		tid := iam.NewTenantID()
		require.NoError(t, client.CreateTenant(ctx, iam.Tenant{ID: tid}))
		view, err := client.ForTenant(ctx, tid)
		require.NoError(t, err)
		tenants = append(tenants, view)
		tenantGroups = append(tenantGroups, iam.GroupByID(tid.String()))
		for range 2 {
			g, err := view.CreateGroup(ctx, iam.NewGroup{Persona: app.Persona})
			require.NoError(t, err)
			apps = append(apps, iam.GroupByID(g.ID))
		}
	}
	verify := func(token string) auth.Verified {
		t.Helper()
		r := httptest.NewRequest("GET", "https://content.test/admin", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		v, err := client.Authenticator().Authenticate(r)
		require.NoError(t, err)
		return v
	}
	for _, tc := range []struct {
		name  string
		group iam.GroupRef
		role  iam.Role
		want  []bool
	}{
		{"root admin", iam.RootGroup(), rootAdmin, []bool{true, true, true, true}},
		{"tenant admin", tenantGroups[0], tenantAdmin, []bool{true, true, false, false}},
		{"app admin", apps[0], appAdmin, []bool{true, false, false, false}},
		{"root owner", iam.RootGroup(), roles.Root.Owner, []bool{true, true, true, true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := authtest.NewUser(t, tenants[0])
			authtest.GrantRole(t, client, tc.group, iam.UserSubject(u.ID), tc.role)
			// Assignment precedes enrollment. SignIn follows the real deferred
			// enrollment/second-factor HTTP flow before returning a full token.
			v := verify(authtest.SignIn(t, tenants[0], u).AccessToken)
			grants, err := client.EffectivePermissions(ctx, v.Identity(), apps)
			require.NoError(t, err)
			for i, group := range apps {
				scope, err := client.Scope(ctx, group)
				require.NoError(t, err)
				for _, p := range []iam.Perm{console, write, moderate} {
					allowed, err := client.Can(ctx, v.Identity(), group, p)
					require.NoError(t, err)
					require.Equal(t, tc.want[i], allowed, "native %s target %d", p, i)
					allowed, err = v.(auth.PermissionChecker).Can(ctx, scope, p.String())
					require.NoError(t, err)
					require.Equal(t, tc.want[i], allowed, "verified %s target %d", p, i)
					require.Equal(t, tc.want[i], covers(grants[group.ID()], p), "effective %s target %d", p, i)
				}
			}
			for _, p := range []iam.Perm{roles.Root.Members.Manage, roles.Root.Credentials.Manage, billingWrite} {
				allowed, err := client.Can(ctx, v.Identity(), iam.RootGroup(), p)
				require.NoError(t, err)
				require.Equal(t, tc.role == roles.Root.Owner, allowed, "owner-only %s", p)
			}
			if tc.role == rootAdmin {
				for i, group := range apps {
					allowed, err := client.Can(ctx, iam.PinnedTo(v.Identity(), apps[0].ID()), group, write)
					require.NoError(t, err)
					require.Equal(t, i == 0, allowed, "app pin target %d", i)
					limited := iam.Within(v.Identity(), write)
					allowed, err = client.Can(ctx, limited, group, write)
					require.NoError(t, err)
					require.True(t, allowed)
					allowed, err = client.Can(ctx, limited, group, moderate)
					require.NoError(t, err)
					require.False(t, allowed, "inherited role bypassed delegated ceiling")
				}
			}
		})
	}

	t.Run("saved grant waits for MFA", func(t *testing.T) {
		u := authtest.NewUser(t, tenants[0])
		v := verify(authtest.SignIn(t, tenants[0], u).AccessToken)
		authtest.GrantRole(t, client, iam.RootGroup(), iam.UserSubject(u.ID), rootAdmin)
		stored, err := client.GroupRoles(ctx, iam.RootGroup(), []iam.Subject{iam.UserSubject(u.ID)})
		require.NoError(t, err)
		require.Equal(t, rootAdmin, stored[iam.UserSubject(u.ID)])
		allowed, err := client.Can(ctx, v.Identity(), apps[0], write)
		require.False(t, allowed)
		require.ErrorIs(t, err, iam.ErrTwoFAEnrollmentRequired)
		_, err = client.EffectivePermissions(ctx, v.Identity(), apps)
		require.ErrorIs(t, err, iam.ErrTwoFAEnrollmentRequired)
	})

	t.Run("app key cannot borrow admin authority", func(t *testing.T) {
		key, err := client.CreateAPIKey(ctx, iam.SystemIdentity(), apps[0], iam.NewAPIKey{Name: "publisher", Role: publisher})
		require.NoError(t, err)
		v := verify(key.Secret)
		for i, group := range apps {
			allowed, err := client.Can(ctx, v.Identity(), group, write)
			require.NoError(t, err)
			require.Equal(t, i == 0, allowed)
			allowed, err = client.Can(ctx, v.Identity(), group, moderate)
			require.NoError(t, err)
			require.False(t, allowed)
		}
		_, err = client.CreateAPIKey(ctx, iam.SystemIdentity(), apps[0], iam.NewAPIKey{Name: "admin", Role: appAdmin})
		require.Error(t, err, "a machine cannot present the content administrator's MFA")
		require.NoError(t, client.RevokeAPIKey(ctx, iam.SystemIdentity(), apps[0], key.APIKey.ID))
		allowed, _ := client.Can(ctx, v.Identity(), apps[0], write)
		require.False(t, allowed, "verified key retained revoked inherited authority")
	})

	t.Run("creator coverage revokes a descendant key", func(t *testing.T) {
		u := authtest.NewUser(t, tenants[0])
		authtest.GrantRole(t, client, iam.RootGroup(), iam.UserSubject(u.ID), issuer)
		key, err := client.CreateAPIKey(ctx, iam.UserIdentity(u.ID), apps[0], iam.NewAPIKey{Name: "issued", Role: publisher})
		require.NoError(t, err)
		require.Equal(t, u.ID, *key.APIKey.CreatedBy)
		v := verify(key.Secret)
		for i, group := range apps {
			allowed, err := client.Can(ctx, v.Identity(), group, write)
			require.NoError(t, err)
			require.Equal(t, i == 0, allowed, "key borrowed creator's global grant at %d", i)
		}
		require.NoError(t, client.RemoveGroupMember(ctx, iam.SystemIdentity(), iam.RootGroup(), iam.UserSubject(u.ID)))
		_, err = client.ResolveAPIKey(ctx, key.Secret)
		require.NoError(t, err, "the app owns its key after the creating administrator leaves")
		allowed, _ := client.Can(ctx, v.Identity(), apps[0], write)
		require.True(t, allowed)
	})

	t.Run("remote application remains app scoped", func(t *testing.T) {
		remote := newFakeIssuer(t)
		require.NoError(t, client.DeclareRemoteApplications(ctx, apps[0], []iam.RemoteApplication{{Issuer: remote.url, Enabled: true, Role: publisher}}))
		registered, err := client.RemoteApplication(ctx, iam.AppByIssuer(remote.url))
		require.NoError(t, err)
		identity := iam.ApplicationIdentity(registered.ID)
		for i, group := range apps {
			allowed, err := client.Can(ctx, identity, group, write)
			require.NoError(t, err)
			require.Equal(t, i == 0, allowed)
			allowed, err = client.Can(ctx, identity, group, moderate)
			require.NoError(t, err)
			require.False(t, allowed)
		}
		_, err = client.SetGroupRole(ctx, iam.SystemIdentity(), apps[0], iam.RemoteApplicationSubject(registered.ID), appAdmin)
		require.Error(t, err, "remote applications cannot hold the MFA-protected admin bundle")
		require.NoError(t, client.DeleteRemoteApplication(ctx, iam.SystemIdentity(), apps[0], registered.ID))
		allowed, _ := client.Can(ctx, identity, apps[0], write)
		require.False(t, allowed, "remote application retained revoked authority")
	})

	t.Run("authoritative parent cannot be rebound", func(t *testing.T) {
		foreign := tenants[1]
		_, err := foreign.CreateGroup(ctx, iam.NewGroup{ID: apps[0].ID(), Persona: app.Persona})
		require.Error(t, err)
		stored, err := client.Group(ctx, apps[0])
		require.NoError(t, err)
		tenant, err := client.Group(ctx, tenantGroups[0])
		require.NoError(t, err)
		require.Equal(t, tenant.TenantID, stored.TenantID)
		_, err = client.CreateGroup(ctx, iam.NewGroup{Persona: app.Persona})
		require.ErrorIs(t, err, iam.ErrTenantRequired, "an unbound app cannot inherit an invented tenant")
	})

	t.Run("assignment revocation is live", func(t *testing.T) {
		u := authtest.NewUser(t, tenants[0])
		authtest.GrantRole(t, client, tenantGroups[0], iam.UserSubject(u.ID), tenantAdmin)
		v := verify(authtest.SignIn(t, tenants[0], u).AccessToken)
		require.NoError(t, client.RemoveGroupMember(ctx, iam.SystemIdentity(), tenantGroups[0], iam.UserSubject(u.ID)))
		for _, group := range apps {
			allowed, err := client.Can(ctx, v.Identity(), group, write)
			require.NoError(t, err)
			require.False(t, allowed)
		}
	})
}

func covers(grants []iam.Perm, permission iam.Perm) bool {
	for _, grant := range grants {
		if permission.Matches(grant) {
			return true
		}
	}
	return false
}
