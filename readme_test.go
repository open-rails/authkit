package authkit_test

import (
	"context"
	"errors"
	"os"
	"regexp"
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

// readmeRoles is README.md's roles block, verbatim. Keep them in step.
var readmeRoles = authkit.RoleConfig{
	Personas: map[string]authkit.Persona{
		"channel": {
			Permissions: []string{
				"channel:posts:edit", "channel:posts:delete", "channel:posts:approve",
				"channel:self:edit",
				"channel:self:delete",
			},
		},
	},
	Roles: []authkit.Role{
		{Persona: "channel", Name: "moderator", Permissions: []string{"channel:posts:*"}},
		{Persona: iam.RootPersona, Name: "admin", Permissions: []string{
			"channel:*",
			"root:users:*",
		}},
	},
}

var errReadmeChannelTaken = errors.New("that channel already exists")

// readmeCreateChannel is README.md's createChannel, verbatim.
func readmeCreateChannel(ctx context.Context, db *pgxpool.Pool, auth *authkit.Auth, name, ownerID string) error {
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		owner := iam.UserSubject(ownerID)
		g, err := auth.CreateGroup(ctx, iam.NewGroup{Persona: "channel", Owner: &owner}, authkit.InTx(tx))
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
// on Gin, checks the routes and permissions the README names, runs the
// README's seed twice, as two boots would, and deletes the channel the way the
// README's delete route does.
func TestReadmeRolesBlock(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := t.Context()
	cfg := testConfig(t)
	cfg.HTTP = authkit.HTTPConfig{DirectPeerIP: true}
	cfg.Roles = readmeRoles
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
	for _, perm := range []iam.Perm{"channel:self:edit", "channel:self:delete", "channel:members:manage"} {
		require.True(t, auth.KnownPermission(perm), perm)
	}

	_, err = pg.Pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS channels (
		name        text PRIMARY KEY,
		description text NOT NULL DEFAULT '',
		group_id    uuid NOT NULL UNIQUE
	)`)
	require.NoError(t, err)
	var adminID string
	for boot := 1; boot <= 2; boot++ {
		admin, err := auth.EnsureUserRole(ctx, iam.UserByEmail("admin@readme.test"), iam.RootGroup(), "admin")
		require.NoError(t, err, "README seed, boot %d", boot)
		adminID = admin.ID
		err = readmeCreateChannel(ctx, pg.Pool, auth, "announcements", admin.ID)
		if boot == 1 {
			require.NoError(t, err)
		} else {
			require.ErrorIs(t, err, errReadmeChannelTaken, "later boots find the channel already made")
		}
	}
	var groupID string
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT group_id::text FROM channels WHERE name = 'announcements'`).Scan(&groupID))
	groups, err := auth.ListGroups(ctx, iam.GroupQuery{Persona: "channel", IncludeDeleted: true})
	require.NoError(t, err)
	require.Len(t, groups.Items, 1, "the second boot's group rolled back with its row")
	require.Equal(t, groupID, groups.Items[0].ID)
	roles, err := auth.GroupRoles(ctx, iam.GroupByID(groupID), []iam.Subject{iam.UserSubject(adminID)})
	require.NoError(t, err)
	require.Equal(t, iam.OwnerRole, roles[iam.UserSubject(adminID)])
	admin := iam.UserActor(adminID)
	for _, perm := range []iam.Perm{"channel:self:edit", "channel:self:delete", "channel:posts:approve"} {
		ok, err := auth.Can(ctx, admin, iam.GroupByID(groupID), perm)
		require.NoError(t, err)
		require.True(t, ok, perm)
	}

	require.NoError(t, pgx.BeginFunc(ctx, pg.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM channels WHERE group_id = $1`, groupID); err != nil {
			return err
		}
		return auth.DeleteGroup(ctx, iam.GroupByID(groupID), authkit.InTx(tx))
	}))
	g, err := auth.Group(ctx, iam.GroupByID(groupID))
	require.NoError(t, err)
	require.NotNil(t, g.DeletedAt)
	ok, err := auth.Can(ctx, admin, iam.GroupByID(groupID), "channel:posts:approve")
	require.NoError(t, err)
	require.False(t, ok, "a deleted group grants nothing")
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
