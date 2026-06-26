package remote_test

import (
	"context"
	"net/http/httptest"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/remote"
	"github.com/open-rails/authkit/server"
	"github.com/stretchr/testify/require"
)

// fakeAuthz is an in-memory authkit.Authorizer — proves remote.Client faithfully
// round-trips the Authorizer slice over HTTP without needing the engine or a DB.
type fakeAuthz struct{}

func (fakeAuthz) Can(_ context.Context, _, _, _, _, perm string) (bool, error) {
	return perm == "root:users:ban", nil
}
func (fakeAuthz) ListEffectivePermissions(_ context.Context, _, _, _, _ string) ([]string, error) {
	return []string{"root:users:ban", "root:content:moderate"}, nil
}
func (fakeAuthz) IsUserAllowed(_ context.Context, userID string) (bool, error) {
	if userID == "missing" {
		return false, authkit.ErrUserNotFound
	}
	return userID != "banned", nil
}
func (fakeAuthz) ListRoleSlugsByUserErr(_ context.Context, _ string) ([]string, error) {
	return []string{"admin"}, nil
}

// the fake satisfies the contract the handler serves.
var _ authkit.Authorizer = fakeAuthz{}

func TestRemoteAuthorizerParity(t *testing.T) {
	ts := httptest.NewServer(server.NewAuthorizerHandler(fakeAuthz{}, "s3cret"))
	defer ts.Close()
	rc := remote.New(ts.URL, "s3cret")
	ctx := context.Background()

	// Can — true and false round-trip.
	ok, err := rc.Can(ctx, "u1", "user", "root", "", "root:users:ban")
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = rc.Can(ctx, "u1", "user", "root", "", "root:nope")
	require.NoError(t, err)
	require.False(t, ok)

	// list endpoints.
	perms, err := rc.ListEffectivePermissions(ctx, "u1", "user", "root", "")
	require.NoError(t, err)
	require.Equal(t, []string{"root:users:ban", "root:content:moderate"}, perms)
	roles, err := rc.ListRoleSlugsByUserErr(ctx, "u1")
	require.NoError(t, err)
	require.Equal(t, []string{"admin"}, roles)

	// IsUserAllowed — bool + error identity across the wire.
	allowed, err := rc.IsUserAllowed(ctx, "u1")
	require.NoError(t, err)
	require.True(t, allowed)
	_, err = rc.IsUserAllowed(ctx, "missing")
	require.ErrorIs(t, err, authkit.ErrUserNotFound) // sentinel survives the round-trip

	// auth seam: wrong token is rejected.
	bad := remote.New(ts.URL, "wrong")
	_, err = bad.Can(ctx, "u1", "user", "root", "", "root:users:ban")
	require.Error(t, err)
}
