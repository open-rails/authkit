package authkit_test

import (
	"context"
	"testing"

	"github.com/open-rails/helpers/userinfo"
	"github.com/open-rails/helpers/userinfo/userinfotest"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// TestUserInfoLookup: Client.UserInfo is a helpers/userinfo.Lookup reading the
// accounts as they are now: verified email, username as the name; a deleted
// account is absent.
func TestUserInfoLookup(t *testing.T) {
	auth, _ := authtest.New(t)
	ctx := context.Background()
	alice, bob, gone := authtest.NewUser(t, auth), authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	_, err := auth.DeleteUsers(ctx, iam.SystemIdentity(), []string{gone.ID})
	require.NoError(t, err)
	user := func(u authtest.User) userinfo.User {
		return userinfo.User{ID: u.ID, Email: u.Email, Name: u.Username, Username: u.Username}
	}
	userinfotest.Check(t, auth.UserInfo(), userinfotest.Fixtures{
		Users:   []userinfo.User{user(alice), user(bob)},
		Unknown: []string{"0192f6a0-0000-7000-8000-00000000c0de", gone.ID},
		Change: func(c userinfo.User) userinfo.User {
			email, name, verified := "changed-"+c.Email, "changed"+c.ID[len(c.ID)-8:], true
			_, err := auth.UpdateUser(ctx, iam.SystemIdentity(), c.ID, iam.UserUpdate{Email: &email, Username: &name, EmailVerified: &verified})
			require.NoError(t, err)
			return userinfo.User{ID: c.ID, Email: email, Name: name, Username: name}
		},
	})

	unproven := "unproven-" + alice.Email
	_, err = auth.UpdateUser(ctx, iam.SystemIdentity(), alice.ID, iam.UserUpdate{Email: &unproven})
	require.NoError(t, err)
	got, err := auth.UserInfo().Get(ctx, []string{alice.ID})
	require.NoError(t, err)
	require.Empty(t, got[alice.ID].Email, "an unverified address is not shown")
	found, err := auth.UserInfo().Search(ctx, unproven, 10)
	require.NoError(t, err)
	require.Empty(t, found, "nor found by search")
}
