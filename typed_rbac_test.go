package authkit_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

// TestChannelDeletionModels runs both ways an app can let channels be
// deleted, side by side. Per channel: an app permission of the channel
// persona, checked in the channel's own group, which its owner holds, and a
// root role holding every channel permission. Global: an app root permission,
// checked on root, which only root roles hold.
func TestChannelDeletionModels(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := t.Context()
	rbac := authkit.NewRoles()
	channel := rbac.Persona("channel")
	postsEdit := channel.Permission("posts", "edit")
	selfDelete := channel.Permission("self", "delete")           // per channel
	channelsDelete := rbac.Root.Permission("channels", "delete") // global
	moderator := channel.Role("moderator", postsEdit)
	channelAdmin := rbac.Root.Role("channel-admin", channel.All())
	siteAdmin := rbac.Root.Role("site-admin", channelsDelete)
	cfg := testConfig(t)
	cfg.Roles = rbac
	auth := newPublicRuntime(t, cfg, pg.Pool)
	t.Cleanup(auth.Close)

	user := func(name string) string {
		u, err := auth.CreateUser(ctx, iam.NewUser{Email: name + "@deletion.test", Username: name})
		require.NoError(t, err)
		return u.ID
	}
	owner, mod, chAdmin, sAdmin := user("owner"), user("moderator"), user("channeladmin"), user("siteadmin")
	founder := iam.UserSubject(owner)
	g, err := auth.CreateGroup(ctx, iam.NewGroup{Persona: channel.Persona, Owner: &founder})
	require.NoError(t, err)
	golang := iam.GroupByID(g.ID)
	grant := func(ref iam.GroupRef, userID string, role iam.Role) {
		_, err := auth.SetGroupRole(ctx, iam.SystemActor(), ref, iam.UserSubject(userID), role)
		require.NoError(t, err)
	}
	grant(golang, mod, moderator)
	grant(iam.RootGroup(), chAdmin, channelAdmin)
	grant(iam.RootGroup(), sAdmin, siteAdmin)

	can := func(userID string, ref iam.GroupRef, perm iam.Perm) bool {
		ok, err := auth.Can(ctx, iam.UserActor(userID), ref, perm)
		require.NoError(t, err)
		return ok
	}
	for _, tc := range []struct {
		who                string
		id                 string
		perChannel, global bool
	}{
		{"the channel's owner", owner, true, false},
		{"its moderator", mod, false, false},
		{"a root role holding channel:*", chAdmin, true, false},
		{"a root role holding only root:channels:delete", sAdmin, false, true},
	} {
		require.Equal(t, tc.perChannel, can(tc.id, golang, selfDelete), "%s, per channel", tc.who)
		require.Equal(t, tc.global, can(tc.id, iam.RootGroup(), channelsDelete), "%s, global", tc.who)
	}
	_, err = auth.Can(ctx, iam.UserActor(owner), golang, channelsDelete)
	require.NoError(t, err, "a root permission asked of a channel is false, not an error")
	require.False(t, can(sAdmin, golang, channelsDelete), "root:channels:delete counts only on root")

	require.Panics(t, func() { verify.RequirePermissionOn(auth, iam.RootGroup(), rbac.Root.Credentials.Manage) }, "root:credentials:manage needs APIKeys or RemoteApplications")

	// Each model gates a route: the per-channel one on the group the route's
	// loader attaches, the global one on root.
	token := func(userID string) string {
		tok, err := auth.MintAccessToken(ctx, userID, iam.AccessTokenOptions{})
		require.NoError(t, err)
		return tok.Value
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	load := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(verify.WithGroup(r.Context(), golang)))
		})
	}
	mux := http.NewServeMux()
	mux.Handle("DELETE /c/golang", load(verify.RequirePermission(auth, selfDelete)(ok)))
	mux.Handle("DELETE /c/unloaded", verify.RequirePermission(auth, selfDelete)(ok))
	mux.Handle("DELETE /channels/golang", verify.RequirePermissionOn(auth, iam.RootGroup(), channelsDelete)(ok))
	status := func(path, userID string) int {
		r := httptest.NewRequest(http.MethodDelete, path, nil)
		r.Header.Set("Authorization", "Bearer "+token(userID))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code
	}
	require.Equal(t, http.StatusNoContent, status("/c/golang", owner))
	require.Equal(t, http.StatusForbidden, status("/c/golang", mod))
	require.Equal(t, http.StatusNoContent, status("/c/golang", chAdmin))
	require.Equal(t, http.StatusForbidden, status("/c/golang", sAdmin))
	require.Equal(t, http.StatusInternalServerError, status("/c/unloaded", owner), "no group attached fails closed")
	require.Equal(t, http.StatusForbidden, status("/channels/golang", owner))
	require.Equal(t, http.StatusNoContent, status("/channels/golang", sAdmin))
}
