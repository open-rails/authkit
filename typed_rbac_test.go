package authkit_test

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// TestStringIdentifiersDoNotCompile builds testdata/stringidents, host code
// passing strings where a role, permission or persona is expected, and
// requires the compiler to refuse exactly the lines marked `// want error`.
func TestStringIdentifiersDoNotCompile(t *testing.T) {
	const pkg = "testdata/stringidents"
	src, err := os.ReadFile(filepath.Join(pkg, "main.go"))
	require.NoError(t, err)
	want := map[int]bool{}
	for i, line := range strings.Split(string(src), "\n") {
		if strings.HasSuffix(line, "// want error") {
			want[i+1] = true
		}
	}
	require.Len(t, want, 6)

	out, err := exec.Command("go", "build", "-o", os.DevNull, "./"+pkg).CombinedOutput()
	require.Error(t, err, "string identifiers compiled:\n%s", out)
	got := map[int]bool{}
	errLine := regexp.MustCompile(`main\.go:(\d+):\d+: `)
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		if m := errLine.FindStringSubmatch(scanner.Text()); m != nil {
			n, err := strconv.Atoi(m[1])
			require.NoError(t, err)
			got[n] = true
		}
	}
	require.Equal(t, want, got, "compiler output:\n%s", out)
}

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
		res, err := auth.AssignGroupRoles(ctx, iam.SystemActor(), ref, []iam.Subject{iam.UserSubject(userID)}, role)
		require.NoError(t, err)
		require.NoError(t, res[0].Err)
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

	require.NotPanics(t, func() { auth.RequirePermission(golang, selfDelete) })
	require.NotPanics(t, func() { auth.RequirePermission(iam.RootGroup(), channelsDelete) })
	require.Panics(t, func() { auth.RequirePermission(iam.RootGroup(), rbac.Root.Roles.Manage) }, "root:roles:manage needs CustomRoles")
}
