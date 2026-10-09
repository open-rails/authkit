package authkit_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/scim"
	"github.com/open-rails/authkit/internal/testscim"
)

const pushToken = "push-token"

// provisioned is an AuthKit pushing to a SCIM server every second.
func provisioned(t *testing.T, server *testscim.Server, edit func(*authkit.ProvisioningTarget, *authkit.ProvisioningConfig)) *authkit.Client {
	t.Helper()
	server.Token = pushToken
	srv := httptest.NewServer(server)
	t.Cleanup(srv.Close)
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		target := authkit.ProvisioningTarget{Name: "billing", URL: srv.URL + "/scim/v2", BearerToken: pushToken}
		c.Provisioning = authkit.ProvisioningConfig{Interval: time.Second, ReconcileInterval: -1}
		if edit != nil {
			edit(&target, &c.Provisioning)
		}
		c.Provisioning.Targets = []authkit.ProvisioningTarget{target}
	}))
	return auth
}

// pushed waits until the server holds want for the account id, or its
// absence when want is nil.
func pushed(t *testing.T, server *testscim.Server, id string, want func(scim.User) bool) scim.User {
	t.Helper()
	var got scim.User
	require.Eventually(t, func() bool {
		u, ok := server.User(id)
		got = u
		if want == nil {
			return !ok
		}
		return ok && want(u)
	}, 30*time.Second, 100*time.Millisecond, "the target never showed the change; it holds %+v", got)
	return got
}

func active(u scim.User) bool { return u.Active != nil && *u.Active }

func bulkOps(t *testing.T, server *testscim.Server) (bulks, ops int, methods map[string]int) {
	t.Helper()
	methods = map[string]int{}
	for _, r := range server.Requests() {
		if r.Path != "/scim/v2/Bulk" {
			methods[r.Method]++
			continue
		}
		var req scim.BulkRequest
		require.NoError(t, json.Unmarshal(r.Body, &req))
		bulks++
		ops += len(req.Operations)
		for _, op := range req.Operations {
			methods["bulk "+op.Method]++
		}
	}
	return bulks, ops, methods
}

// TestProvisioningPush: accounts reach a new target through its initial
// sync, in bulk requests within its limits, and every change after it (an
// email, a username, a ban, a deletion, a purge) follows within an interval.
func TestProvisioningPush(t *testing.T) {
	server := testscim.New(true, 2)
	auth := provisioned(t, server, nil)
	ctx := context.Background()
	alice, bob, carol := authtest.NewUser(t, auth), authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	require.NoError(t, auth.Start(ctx))

	for _, u := range []authtest.User{alice, bob, carol} {
		got := pushed(t, server, u.ID, active)
		require.Equal(t, u.Username, got.UserName)
		require.Equal(t, u.Email, got.PrimaryEmail())
		require.Equal(t, u.Username, got.Name.Formatted)
		require.Equal(t, []string{scim.SchemaUser}, got.Schemas)
	}
	bulks, ops, methods := bulkOps(t, server)
	require.GreaterOrEqual(t, bulks, 2, "three users at two operations a request")
	require.Equal(t, 3, ops, "each user once: the outbox and the initial sync coalesce")
	require.Equal(t, 3, methods["bulk POST"])
	require.Zero(t, methods[http.MethodPost], "a target with bulk gets no single creates")

	t.Run("email change", func(t *testing.T) {
		email, verified := "changed-"+alice.Email, true
		_, err := auth.UpdateUser(ctx, iam.SystemIdentity(), alice.ID, iam.UserUpdate{Email: &email, EmailVerified: &verified})
		require.NoError(t, err)
		pushed(t, server, alice.ID, func(u scim.User) bool { return u.PrimaryEmail() == email })
	})
	t.Run("username change", func(t *testing.T) {
		name := "renamed" + alice.ID[:8]
		_, err := auth.UpdateUser(ctx, iam.SystemIdentity(), alice.ID, iam.UserUpdate{Username: &name})
		require.NoError(t, err)
		got := pushed(t, server, alice.ID, func(u scim.User) bool { return u.UserName == name })
		require.Equal(t, name, got.DisplayName)
	})
	t.Run("an unverified email is not pushed", func(t *testing.T) {
		email := "unproven-" + bob.Email
		_, err := auth.UpdateUser(ctx, iam.SystemIdentity(), bob.ID, iam.UserUpdate{Email: &email})
		require.NoError(t, err)
		pushed(t, server, bob.ID, func(u scim.User) bool { return len(u.Emails) == 0 })
	})
	t.Run("deactivation", func(t *testing.T) {
		require.NoError(t, auth.Ban(ctx, iam.SystemIdentity(), bob.ID, iam.Ban{Reason: "spam"}))
		pushed(t, server, bob.ID, func(u scim.User) bool { return !active(u) })
		require.NoError(t, auth.Unban(ctx, iam.SystemIdentity(), bob.ID))
		pushed(t, server, bob.ID, active)
	})
	t.Run("a temporary ban ends on the target too", func(t *testing.T) {
		until := time.Now().Add(3 * time.Second)
		require.NoError(t, auth.Ban(ctx, iam.SystemIdentity(), bob.ID, iam.Ban{Reason: "cool off", Until: &until}))
		pushed(t, server, bob.ID, func(u scim.User) bool { return !active(u) })
		pushed(t, server, bob.ID, active)
	})
	t.Run("deletion", func(t *testing.T) {
		_, err := auth.DeleteUsers(ctx, iam.SystemIdentity(), []string{carol.ID})
		require.NoError(t, err)
		pushed(t, server, carol.ID, func(u scim.User) bool { return !active(u) })
		res, err := auth.PurgeUsers(ctx, []string{carol.ID})
		require.NoError(t, err)
		require.NoError(t, res[0].Err)
		pushed(t, server, carol.ID, nil)
		_, _, methods := bulkOps(t, server)
		require.Equal(t, 1, methods["bulk DELETE"])
	})

	targets, err := auth.ProvisioningTargets(ctx)
	require.NoError(t, err)
	require.Len(t, targets, 1)
	status := targets[0]
	require.Equal(t, "billing", status.Name)
	require.NotNil(t, status.SyncedAt)
	require.NotNil(t, status.LastSuccessAt)
	require.Nil(t, status.FailingSince)
	require.Nil(t, status.LastError)
	require.Zero(t, status.Backlog)
}

// TestProvisioningRetries: a target that fails keeps every change pending,
// reports since when it fails, and receives the changes once it recovers.
func TestProvisioningRetries(t *testing.T) {
	server := testscim.New(true, 10)
	auth := provisioned(t, server, nil)
	ctx := context.Background()
	server.FailNext(3)
	alice := authtest.NewUser(t, auth)
	require.NoError(t, auth.Start(ctx))

	require.Eventually(t, func() bool {
		targets, err := auth.ProvisioningTargets(ctx)
		return err == nil && targets[0].FailingSince != nil && targets[0].Backlog == 1 && targets[0].LastError != nil
	}, 30*time.Second, 100*time.Millisecond, "the failure is reported")
	pushed(t, server, alice.ID, active)
	require.Eventually(t, func() bool {
		targets, err := auth.ProvisioningTargets(ctx)
		return err == nil && targets[0].FailingSince == nil && targets[0].Backlog == 0 && targets[0].LastSuccessAt != nil
	}, 30*time.Second, 100*time.Millisecond, "the recovery is reported")

	t.Run("a refused user waits; the others go on", func(t *testing.T) {
		// Another client holds this username: the target refuses bob's create.
		bob := authtest.NewUser(t, auth)
		server.Add(scim.User{UserName: bob.Username, ExternalID: "someone-else"})
		carol := authtest.NewUser(t, auth)
		pushed(t, server, carol.ID, active)
		require.Eventually(t, func() bool {
			targets, err := auth.ProvisioningTargets(ctx)
			return err == nil && targets[0].FailingSince != nil && targets[0].Backlog == 1
		}, 30*time.Second, 100*time.Millisecond)
		server.Remove("someone-else")
		name := "freed" + bob.ID[:8]
		_, err := auth.UpdateUser(ctx, iam.SystemIdentity(), bob.ID, iam.UserUpdate{Username: &name})
		require.NoError(t, err)
		pushed(t, server, bob.ID, func(u scim.User) bool { return u.UserName == name })
	})
}

// TestProvisioningWithoutBulk: a target without bulk gets the same changes
// as single requests.
func TestProvisioningWithoutBulk(t *testing.T) {
	server := testscim.New(false, 0)
	auth := provisioned(t, server, nil)
	ctx := context.Background()
	alice := authtest.NewUser(t, auth)
	require.NoError(t, auth.Start(ctx))
	pushed(t, server, alice.ID, active)
	require.NoError(t, auth.Ban(ctx, iam.SystemIdentity(), alice.ID, iam.Ban{Reason: "spam"}))
	pushed(t, server, alice.ID, func(u scim.User) bool { return !active(u) })
	_, err := auth.DeleteUsers(ctx, iam.SystemIdentity(), []string{alice.ID})
	require.NoError(t, err)
	res, err := auth.PurgeUsers(ctx, []string{alice.ID})
	require.NoError(t, err)
	require.NoError(t, res[0].Err)
	pushed(t, server, alice.ID, nil)
	bulks, _, methods := bulkOps(t, server)
	require.Zero(t, bulks)
	require.Equal(t, 1, methods[http.MethodPost])
	require.Equal(t, 1, methods[http.MethodPut])
	require.Equal(t, 1, methods[http.MethodDelete])
}

// TestProvisioningReconciles: reconciliation finds what changed at the
// target behind AuthKit's back and repairs it, and adopts a user the target
// already held.
func TestProvisioningReconciles(t *testing.T) {
	server := testscim.New(true, 10)
	auth := provisioned(t, server, func(_ *authkit.ProvisioningTarget, p *authkit.ProvisioningConfig) {
		p.ReconcileInterval = 2 * time.Second
	})
	ctx := context.Background()
	alice, bob, carol := authtest.NewUser(t, auth), authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	// The target already holds carol from an earlier sync.
	server.Add(scim.User{Schemas: []string{scim.SchemaUser}, ExternalID: carol.ID, UserName: carol.Username})
	require.NoError(t, auth.Start(ctx))
	pushed(t, server, alice.ID, active)
	pushed(t, server, carol.ID, func(u scim.User) bool { return u.PrimaryEmail() == carol.Email })
	require.Equal(t, 3, server.Len(), "carol was adopted, not created twice")

	server.Edit(alice.ID, func(u *scim.User) { u.Emails = []scim.Email{{Value: "drifted@example.com", Primary: true}} })
	server.Remove(bob.ID)
	pushed(t, server, alice.ID, func(u scim.User) bool { return u.PrimaryEmail() == alice.Email })
	pushed(t, server, bob.ID, active)
	require.Equal(t, 3, server.Len())
}

// TestProvisioningInProcess: an embedded service provider is called through
// its handler, with no network.
func TestProvisioningInProcess(t *testing.T) {
	server := testscim.New(true, 10)
	server.Token = pushToken
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Provisioning = authkit.ProvisioningConfig{Interval: time.Second, Targets: []authkit.ProvisioningTarget{
			{Name: "embedded", Handler: server, BearerToken: pushToken},
		}}
	}))
	alice := authtest.NewUser(t, auth)
	require.NoError(t, auth.Start(context.Background()))
	pushed(t, server, alice.ID, active)
}

// TestProvisioningOutboxCoversEveryWriter: every way an account changes what
// a SCIM User shows records it for the target in the change's transaction,
// whichever operation writes it; a change it does not show records nothing.
// (TestProvisioningTriggersWatchWhatIsPushed keeps the triggers' columns
// complete.)
func TestProvisioningOutboxCoversEveryWriter(t *testing.T) {
	ctx := context.Background()
	rbac := authkit.NewRoles()
	support := rbac.Root.Role("support", rbac.Root.Users.Read)
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.Roles = rbac }))
	var users []authtest.User
	for range 9 {
		users = append(users, authtest.NewUser(t, auth))
	}
	require.NoError(t, auth.Ban(ctx, iam.SystemIdentity(), users[4].ID, iam.Ban{Reason: "earlier"}))
	_, err := auth.DeleteUsers(ctx, iam.SystemIdentity(), []string{users[6].ID})
	require.NoError(t, err)

	// A sibling app on the same accounts declares the target: from now on,
	// every change is recorded for it, whichever app makes it.
	pusher := authtest.Replica(t, auth, authtest.WithConfig(func(c *authkit.Config) {
		c.Token.Issuer = "https://billing-host.example.com"
		c.Provisioning = authkit.ProvisioningConfig{Targets: []authkit.ProvisioningTarget{{Name: "billing", URL: "https://billing.example.com/scim/v2"}}}
	}))
	backlog := func() int {
		targets, err := pusher.ProvisioningTargets(ctx)
		require.NoError(t, err)
		return targets[0].Backlog
	}
	require.Zero(t, backlog())

	email, name, unverified, verified := "new-"+users[0].Email, "renamed"+users[1].ID[:8], false, true
	phone, language := "+14155550123", "fr"
	writers := []struct {
		name  string
		write func() error
	}{
		{"email", func() error {
			_, err := auth.UpdateUser(ctx, iam.SystemIdentity(), users[0].ID, iam.UserUpdate{Email: &email, EmailVerified: &verified})
			return err
		}},
		{"username", func() error {
			_, err := auth.UpdateUser(ctx, iam.SystemIdentity(), users[1].ID, iam.UserUpdate{Username: &name})
			return err
		}},
		{"email verification", func() error {
			_, err := auth.UpdateUser(ctx, iam.SystemIdentity(), users[2].ID, iam.UserUpdate{EmailVerified: &unverified})
			return err
		}},
		{"ban", func() error { return auth.Ban(ctx, iam.SystemIdentity(), users[3].ID, iam.Ban{Reason: "spam"}) }},
		{"unban", func() error { return auth.Unban(ctx, iam.SystemIdentity(), users[4].ID) }},
		{"deletion", func() error {
			_, err := auth.DeleteUsers(ctx, iam.SystemIdentity(), []string{users[5].ID})
			return err
		}},
		{"restore", func() error {
			res, err := auth.RestoreUsers(ctx, iam.SystemIdentity(), []string{users[6].ID})
			if err == nil {
				err = res[0].Err
			}
			return err
		}},
		{"creation", func() error {
			_, err := auth.CreateUser(ctx, iam.NewUser{Email: "created-" + users[0].Email, Username: "created" + users[0].ID[:8]})
			return err
		}},
		{"import", func() error {
			_, err := auth.ImportUsers(ctx, []iam.ImportUser{{Email: "imported-" + users[0].Email, Username: "imported" + users[0].ID[:8]}}, iam.ImportOptions{})
			return err
		}},
		{"a role for a new address", func() error {
			_, err := auth.EnsureUserRole(ctx, iam.RootGroup(), iam.UserByEmail("staff-"+users[0].Email), support)
			return err
		}},
	}
	for i, w := range writers {
		require.NoError(t, w.write(), w.name)
		require.Equal(t, i+1, backlog(), "%s records the account for the target", w.name)
	}

	quiet := users[8]
	_, err = auth.UpdateUser(ctx, iam.SystemIdentity(), quiet.ID, iam.UserUpdate{Phone: &phone, PreferredLanguage: &language})
	require.NoError(t, err)
	require.NoError(t, auth.PatchPublicMetadata(ctx, iam.SystemIdentity(), quiet.ID, map[string]any{"bio": "hi"}))
	authtest.SignIn(t, auth, quiet)
	require.Equal(t, len(writers), backlog(), "a change a SCIM User does not show records nothing")
}
