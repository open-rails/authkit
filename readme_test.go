package authkit_test

import (
	"testing"

	"github.com/gin-gonic/gin"
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
			Permissions: []string{"channel:posts:edit", "channel:posts:delete", "channel:posts:approve"},
			Creation:    authkit.GroupCreation{Enabled: true, ReservedSlugs: []string{"announcements"}},
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

// TestReadmeRolesBlock builds AuthKit with README.md's roles block, mounts it
// on Gin, checks the routes the README names and runs the README's seed twice,
// as two boots would.
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
		"POST /api/v1/channel",
		"PUT /api/v1/channel/{instance_slug}/members/{user}/roles/{role}",
		"GET /api/v1/admin/users",
		"POST /api/v1/admin/users/{user_id}/ban",
		"POST /api/v1/admin/users/{user_id}/unban",
	} {
		require.Contains(t, auth.Patterns(), route)
	}

	for boot := 1; boot <= 2; boot++ {
		admin, err := auth.EnsureUserRole(ctx, iam.OperatorActor(), iam.RootGroup(), iam.UserByEmail("admin@readme.test"), "admin")
		require.NoError(t, err, "README seed, boot %d", boot)
		_, created, err := auth.CreateGroup(ctx, iam.UserActor(admin.ID), iam.NewGroup{Persona: "channel", Slug: "announcements"})
		require.NoError(t, err, "README seed, boot %d", boot)
		require.Equal(t, boot == 1, created, "later boots find the channel already made")
	}
}
