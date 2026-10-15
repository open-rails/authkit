package authkit_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/scim"
	"github.com/open-rails/authkit/internal/testscim"
	"github.com/stretchr/testify/require"
)

func TestProvisioningKeepsTenantTargetsAndPurgedReceiptsSeparate(t *testing.T) {
	base, _ := authtest.New(t)
	ctx := t.Context()
	a, err := base.CreateUser(ctx, iam.NewUser{Email: "same@example.test", EmailVerified: true, Username: "sameuser"})
	require.NoError(t, err)
	bID := iam.NewTenantID()
	require.NoError(t, base.CreateTenant(ctx, iam.Tenant{ID: bID}))
	b, err := base.ForTenant(ctx, bID)
	require.NoError(t, err)
	bUser, err := b.CreateUser(ctx, iam.NewUser{Email: "same@example.test", EmailVerified: true, Username: "sameuser"})
	require.NoError(t, err)
	aServer, bServer := testscim.New(true, 10), testscim.New(true, 10)
	aServer.Token, bServer.Token = pushToken, pushToken
	aHTTP, bHTTP := httptest.NewServer(aServer), httptest.NewServer(bServer)
	t.Cleanup(aHTTP.Close)
	t.Cleanup(bHTTP.Close)
	configure := authtest.WithConfig(func(c *authkit.Config) {
		c.Provisioning = authkit.ProvisioningConfig{
			Interval: time.Second, ReconcileInterval: -1,
			Targets: []authkit.ProvisioningTarget{
				{Name: "tenant-a", TenantID: a.TenantID, URL: aHTTP.URL + "/scim/v2", BearerToken: pushToken},
				{Name: "tenant-b", TenantID: bID, URL: bHTTP.URL + "/scim/v2", BearerToken: pushToken},
			},
		}
	})
	pusher := authtest.Replica(t, base, configure)
	require.NoError(t, pusher.Start(ctx))
	pushed(t, aServer, a.ID, active)
	pushed(t, bServer, bUser.ID, active)
	assertSeparate := func() {
		t.Helper()
		_, crossed := aServer.User(bUser.ID)
		require.False(t, crossed, "B's account reached A's target")
		_, crossed = bServer.User(a.ID)
		require.False(t, crossed, "A's account reached B's target")
	}
	assertSeparate()
	writer, err := pusher.ForTenant(ctx, bID)
	require.NoError(t, err)
	name := "renamedinb"
	_, err = writer.UpdateUser(ctx, iam.SystemIdentity(), bUser.ID, iam.UserUpdate{Username: &name})
	require.NoError(t, err)
	pushed(t, bServer, bUser.ID, func(u scim.User) bool { return u.UserName == name })
	after, ok := aServer.User(a.ID)
	require.True(t, ok)
	require.Equal(t, "sameuser", after.UserName)

	// Keep B offline through final account purge. Its queued deletion must
	// retain B's tenant even after the account row no longer exists.
	bServer.FailNext(1000)
	results, err := writer.PurgeUsers(ctx, []string{bUser.ID})
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Err)
	require.Eventually(t, func() bool {
		users, err := writer.Users(ctx, []string{bUser.ID})
		return err == nil && len(users) == 0
	}, 30*time.Second, 50*time.Millisecond, "the account was not purged")
	require.Eventually(t, func() bool {
		targets, err := writer.ProvisioningTargets(ctx)
		if err != nil {
			return false
		}
		for _, target := range targets {
			if target.Name == "tenant-b" {
				return target.Backlog > 0
			}
		}
		return false
	}, 30*time.Second, 50*time.Millisecond, "the purged account lost its pending B delivery")
	require.NoError(t, pusher.Close(ctx))
	bServer.FailNext(0)
	// The restarted engine still defaults to A; the durable B target and
	// tombstone determine where the deletion goes.
	pusher = authtest.Replica(t, base, configure)
	require.NoError(t, pusher.Start(ctx))
	writer, err = pusher.ForTenant(ctx, bID)
	require.NoError(t, err)
	pushed(t, bServer, bUser.ID, nil)
	pushed(t, aServer, a.ID, active)
	require.Eventually(t, func() bool {
		aTargets, err := pusher.ProvisioningTargets(ctx)
		if err != nil || len(aTargets) != 1 || aTargets[0].Name != "tenant-a" {
			return false
		}
		bTargets, err := writer.ProvisioningTargets(ctx)
		if err != nil || len(bTargets) != 1 || bTargets[0].Name != "tenant-b" {
			return false
		}
		targets := append(aTargets, bTargets...)
		for _, target := range targets {
			if target.Backlog != 0 {
				return false
			}
		}
		return true
	}, 30*time.Second, 50*time.Millisecond)
	assertSeparate()
	for _, request := range aServer.Requests() {
		require.NotContains(t, string(request.Body), bUser.ID)
	}
	for _, request := range bServer.Requests() {
		require.NotContains(t, string(request.Body), a.ID)
	}
}
