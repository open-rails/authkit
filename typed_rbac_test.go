package authkit_test

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

// TestChannelDeletionModels runs both ways an app can let channels be
// deleted, side by side. Per channel: an app permission of the channel
// persona, checked in the channel's own group, which its owner holds, as do
// the root owner and a root role holding every channel permission. Global: an
// app root permission, checked on root, which only root roles hold.
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
	cfg.TwoFactor.Mode = iam.TwoFactorDisabled // root:owner needs MFA; this test is about reach
	auth := newPublicRuntime(t, cfg, pg.Pool)
	t.Cleanup(auth.Close)

	user := func(name string) string {
		u, err := auth.CreateUser(ctx, iam.NewUser{Email: name + "@deletion.test", Username: name})
		require.NoError(t, err)
		return u.ID
	}
	owner, mod, chAdmin, sAdmin, siteOwner := user("owner"), user("moderator"), user("channeladmin"), user("siteadmin"), user("siteowner")
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
	grant(iam.RootGroup(), siteOwner, rbac.Root.Owner)

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
		{"the root owner", siteOwner, true, true},
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
	require.Equal(t, http.StatusNoContent, status("/c/golang", siteOwner), "the root owner reaches every channel")
	require.Equal(t, http.StatusForbidden, status("/c/golang", sAdmin), "a root role without channel:* does not")
	require.Equal(t, http.StatusInternalServerError, status("/c/unloaded", owner), "no group attached fails closed")
	require.Equal(t, http.StatusForbidden, status("/channels/golang", owner))
	require.Equal(t, http.StatusNoContent, status("/channels/golang", sAdmin))
	require.Equal(t, http.StatusNoContent, status("/channels/golang", siteOwner))
}

// RolePermissions reads a role's grants from the running catalog, includes
// flattened, so a host compares roles (a no-escalation check) without a copy
// of its catalog.
func TestRolePermissions(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	rbac := authkit.NewRoles()
	channel := rbac.Persona("channel")
	postsRead := channel.Permission("posts", "read")
	postsEdit := channel.Permission("posts", "edit")
	reader := channel.Role("reader", postsRead)
	moderator := channel.Role("moderator", reader, postsEdit, channel.Members.Read)
	cfg := testConfig(t)
	cfg.Roles = rbac
	auth := newPublicRuntime(t, cfg, pg.Pool)
	t.Cleanup(auth.Close)

	grants := func(role iam.Role) []iam.Perm {
		t.Helper()
		perms, err := auth.RolePermissions(role)
		require.NoError(t, err)
		return perms
	}
	require.Equal(t, []iam.Perm{postsEdit, channel.Members.Read, postsRead}, grants(moderator), "own grants, then includes")
	require.Equal(t, []iam.Perm{channel.All()}, grants(channel.Owner))
	require.Equal(t, []iam.Perm{rbac.Root.All(), channel.All()}, grants(rbac.Root.Owner), "the root owner holds every persona")
	parsed, err := auth.Role("channel:reader")
	require.NoError(t, err)
	require.Equal(t, []iam.Perm{postsRead}, grants(parsed))

	// No escalation: a grantor may hand out a role only when its own grants
	// cover every permission the role grants.
	covers := func(grantor, role iam.Role) bool {
		for _, perm := range grants(role) {
			if !slices.ContainsFunc(grants(grantor), perm.Matches) {
				return false
			}
		}
		return true
	}
	require.True(t, covers(moderator, reader))
	require.False(t, covers(reader, moderator))
	require.True(t, covers(channel.Owner, moderator))

	// Roles of another catalog: one this app never declared, and one of a
	// persona it does not have.
	elsewhere := authkit.NewRoles()
	ghost := elsewhere.Persona("channel").Role("ghost")
	shop := elsewhere.Persona("shop")
	clerk := shop.Role("clerk", shop.All())
	for role, want := range map[iam.Role]error{ghost: iam.ErrRoleNotAssignable, clerk: iam.ErrUnknownGroupPersona, {}: iam.ErrRoleNotAssignable} {
		_, err := auth.RolePermissions(role)
		require.ErrorIs(t, err, want, role.String())
	}
}
