package apitest_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// Staff who read users read each provisioning target's delivery.
func TestAdminProvisioningTargets(t *testing.T) {
	rbac := authkit.NewRoles()
	support := rbac.Root.Role("support", rbac.Root.Users.Read)
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Roles = rbac
		c.TwoFactor.Mode = iam.TwoFactorDisabled
		c.Provisioning = authkit.ProvisioningConfig{Targets: []authkit.ProvisioningTarget{{Name: "billing", URL: "https://billing.example.com/scim/v2"}}}
	}))
	a := newAPI(t, auth)
	staff, plain := authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(staff.ID), support)

	var page iam.ListPage[iam.ProvisioningTarget]
	expect(t, http.StatusOK, a.get("/admin/provisioning/targets", authtest.SignIn(t, auth, staff).AccessToken)).decode(t, &page)
	require.Len(t, page.Items, 1)
	target := page.Items[0]
	require.Equal(t, "billing", target.Name)
	require.Equal(t, 2, target.Backlog, "both accounts wait: nothing has run")
	require.Nil(t, target.SyncedAt)
	require.Nil(t, target.LastSuccessAt)
	require.Nil(t, target.FailingSince)

	expect(t, http.StatusForbidden, a.get("/admin/provisioning/targets", authtest.SignIn(t, auth, plain).AccessToken))
}
