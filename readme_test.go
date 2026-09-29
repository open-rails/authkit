package authkit_test

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	authkitgin "github.com/open-rails/authkit/adapters/gin"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// README.md's roles block, verbatim. Keep them in step.
var (
	rbac = authkit.NewRoles()

	// Persona's are types of permission groups. root (the whole site) exists by default.
	// we'll have permission group per reddit-channel, like /c/golang
	Channel = rbac.Persona("channel")

	// Our own custom permissions, in addition to the ones that authkit includes automatically.
	PostsEdit     = Channel.Permission("posts", "edit")
	PostsDelete   = Channel.Permission("posts", "delete")
	PostsApprove  = Channel.Permission("posts", "approve")
	ChannelEdit   = Channel.Permission("self", "edit")   // change the channel's own data: its name, description and rules
	ChannelDelete = Channel.Permission("self", "delete") // delete the channel ("self" is just our name for the channel itself)

	// Roles are bundles of permissions, scoped to a specific persona.
	// There is always a singleton persona; root
	Moderator = Channel.Role("moderator", Channel.Resource("posts").All()) // edit, delete and approve posts
	Admin     = rbac.Root.Role("admin",
		Channel.All(),         // everything in every channel, deleting it included
		rbac.Root.Users.All(), // read, ban, delete and manage user accounts
	)
)

var errReadmeChannelTaken = errors.New("that channel already exists")

// Our application-specific table
const channelsTable = `CREATE TABLE IF NOT EXISTS channels (
	name        text PRIMARY KEY,
	description text NOT NULL DEFAULT '',
	group_id    uuid NOT NULL UNIQUE
)`

// readmeCreateChannel is README.md's createChannel, verbatim.
func readmeCreateChannel(ctx context.Context, db *pgxpool.Pool, auth *authkit.Client, name, ownerID string) error {
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		owner := iam.UserSubject(ownerID)
		g, err := auth.CreateGroup(ctx, iam.NewGroup{Persona: Channel.Persona, Owner: &owner}, authkit.InTx(tx))
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO channels (name, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, name, g.ID)
		if err == nil && tag.RowsAffected() == 0 {
			err = errReadmeChannelTaken // rolling back takes the new group with it
		}
		return err
	})
}

// TestReadmeRolesBlock builds AuthKit with README.md's roles block, mounts it
// on Gin, checks the routes and permissions the README names, boots twice the
// way run() does (seed the admin, open /c/announcements), checks who may edit
// and delete a channel, and deletes one the way the README's delete route does.
func TestReadmeRolesBlock(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := t.Context()
	cfg := testConfig(t)
	cfg.HTTP = authkit.HTTPConfig{DirectPeerIP: true}
	cfg.Roles = rbac
	auth, err := authkit.New(ctx, cfg, authkit.Deps{Postgres: pg.Pool})
	require.NoError(t, err, "README roles block: authkit.New must accept it")
	t.Cleanup(auth.Close)

	gin.SetMode(gin.TestMode)
	require.NoError(t, authkitgin.Mount(gin.New(), auth))
	for _, route := range []string{
		"GET /.well-known/jwks.json",
		"PUT /api/v1/groups/{group_id}/members/{user}/roles/{role}",
		"GET /api/v1/admin/users",
		"POST /api/v1/admin/users/{user_id}/ban",
		"POST /api/v1/admin/users/{user_id}/unban",
	} {
		require.Contains(t, auth.Patterns(), route)
	}
	for _, perm := range []iam.Perm{PostsEdit, PostsDelete, PostsApprove, ChannelEdit, ChannelDelete, Channel.Members.Read, Channel.Members.Manage, rbac.Root.Users.Ban} {
		require.True(t, auth.KnownPermission(perm), perm)
	}
	require.False(t, auth.KnownPermission(Channel.Credentials.Manage), "APIKeys and RemoteApplications are off")
	// A name read at run time resolves to the declared value.
	perm, err := auth.Permission("channel:self:delete")
	require.NoError(t, err)
	require.Equal(t, ChannelDelete, perm)
	role, err := auth.Role(iam.RootPersona, "admin")
	require.NoError(t, err)
	require.Equal(t, Admin, role)

	var adminID string
	for boot := 1; boot <= 2; boot++ {
		_, err := pg.Pool.Exec(ctx, channelsTable)
		require.NoError(t, err)
		admin, err := auth.EnsureUserRole(ctx, iam.UserByEmail("admin@readme.test"), iam.RootGroup(), Admin) // seed
		require.NoError(t, err, "README seed, boot %d", boot)
		adminID = admin.ID
		err = readmeCreateChannel(ctx, pg.Pool, auth, "announcements", admin.ID)
		if boot == 1 {
			require.NoError(t, err)
		} else {
			require.ErrorIs(t, err, errReadmeChannelTaken, "later boots find the channel already made")
		}
	}
	var announcements string
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT group_id::text FROM channels WHERE name = 'announcements'`).Scan(&announcements))
	groups, err := auth.ListGroups(ctx, iam.GroupQuery{Persona: Channel.Persona, IncludeDeleted: true})
	require.NoError(t, err)
	require.Len(t, groups.Items, 1, "the second boot's group rolled back with its row")
	require.Equal(t, announcements, groups.Items[0].ID)
	roles, err := auth.GroupRoles(ctx, iam.GroupByID(announcements), []iam.Subject{iam.UserSubject(adminID)})
	require.NoError(t, err)
	require.Equal(t, Channel.Owner, roles[iam.UserSubject(adminID)])

	// /c/golang: an owner edits and deletes it; its moderator only moderates;
	// the admin does anything, in every channel.
	newUser := func(name string) string {
		u, err := auth.CreateUser(ctx, iam.NewUser{Email: name + "@readme.test", Username: name})
		require.NoError(t, err)
		return u.ID
	}
	ownerID, bobID := newUser("golangowner"), newUser("bobmoderator")
	require.NoError(t, readmeCreateChannel(ctx, pg.Pool, auth, "golang", ownerID))
	var golang string
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT group_id::text FROM channels WHERE name = 'golang'`).Scan(&golang))
	res, err := auth.AssignGroupRoles(ctx, iam.UserActor(ownerID), iam.GroupByID(golang), []iam.Subject{iam.UserSubject(bobID)}, Moderator)
	require.NoError(t, err)
	require.NoError(t, res[0].Err, "the owner pins the badge on Bob")
	can := func(userID, groupID string, perm iam.Perm) bool {
		ok, err := auth.Can(ctx, iam.UserActor(userID), iam.GroupByID(groupID), perm)
		require.NoError(t, err)
		return ok
	}
	for _, perm := range []iam.Perm{ChannelEdit, ChannelDelete, PostsApprove} {
		require.True(t, can(ownerID, golang, perm), perm)
		require.True(t, can(adminID, golang, perm), perm)
		require.False(t, can(ownerID, announcements, perm), "an owner of /c/golang only")
	}
	require.True(t, can(bobID, golang, PostsEdit))
	require.False(t, can(bobID, golang, ChannelEdit), "moderators can't edit the channel")
	require.False(t, can(bobID, golang, ChannelDelete), "or delete it")
	require.False(t, can(bobID, announcements, PostsEdit), "Bob moderates /c/golang and nowhere else")

	require.NoError(t, pgx.BeginFunc(ctx, pg.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM channels WHERE group_id = $1`, golang); err != nil {
			return err
		}
		return auth.DeleteGroup(ctx, iam.GroupByID(golang), authkit.InTx(tx))
	}))
	g, err := auth.Group(ctx, iam.GroupByID(golang))
	require.NoError(t, err)
	require.NotNil(t, g.DeletedAt)
	require.False(t, can(adminID, golang, PostsApprove), "a deleted group grants nothing")
}

// TestReadmeSnippetsAreInTheExample keeps README.md honest: every Go snippet in it
// must appear, verbatim, in examples/reddit/main.go, which CI builds and vets.
func TestReadmeSnippetsAreInTheExample(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	require.NoError(t, err)
	example, err := os.ReadFile("examples/reddit/main.go")
	require.NoError(t, err)
	blocks := regexp.MustCompile("(?s)```go\n(.*?)```").FindAllStringSubmatch(string(readme), -1)
	require.NotEmpty(t, blocks, "README has Go snippets")
	for i, b := range blocks {
		require.Contains(t, string(example), b[1], "README Go snippet %d is not in examples/reddit/main.go", i+1)
	}
}

// TestReadmeRoutesTable requires README.md's route tables to list exactly the
// routes Mount serves for the README's config: every row, none missing, none
// extra. A row's extra `/segment` names a sibling route: it replaces the last
// segment of the row's path.
func TestReadmeRoutesTable(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := testConfig(t)
	cfg.HTTP = authkit.HTTPConfig{DirectPeerIP: true}
	cfg.Roles = rbac
	auth, err := authkit.New(t.Context(), cfg, authkit.Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(auth.Close)

	readme, err := os.ReadFile("README.md")
	require.NoError(t, err)
	row := regexp.MustCompile("(?m)^\\| (`[A-Z]+ /[^|]*) \\|")
	code := regexp.MustCompile("`([^`]*)`")
	var listed []string
	for _, m := range row.FindAllStringSubmatch(string(readme), -1) {
		cells := code.FindAllStringSubmatch(m[1], -1)
		method, path, _ := strings.Cut(cells[0][1], " ")
		listed = append(listed, method+" "+path)
		for _, sibling := range cells[1:] {
			listed = append(listed, method+" "+path[:strings.LastIndex(path, "/")]+sibling[1])
		}
	}
	require.NotEmpty(t, listed)
	require.ElementsMatch(t, auth.Patterns(), listed, "README.md's route tables must list exactly the mounted routes")
}
