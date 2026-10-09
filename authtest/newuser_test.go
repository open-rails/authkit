package authtest_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
)

const sharedSchemaEnv = "AUTHTEST_SHARED_SCHEMA"

var generatedName = regexp.MustCompile(`^user[0-9a-f]{16}$`)

// Two test processes sharing one schema create accounts with NewUser side by
// side: this test, then a child run of this test on the same schema. Names
// are random, so neither process collides with the other's.
func TestNewUserAcrossProcessesSharingASchema(t *testing.T) {
	if schema := os.Getenv(sharedSchemaEnv); schema != "" {
		// The child: print the usernames NewUser gives it in the parent's schema.
		auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.Database.Schema = schema }))
		for range 3 {
			fmt.Println(authtest.NewUser(t, auth).Username)
		}
		return
	}
	ctx := t.Context()
	pool, err := pgxpool.New(ctx, testdb.URL(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	schema := fmt.Sprintf("authtest_shared_%d_%d", os.Getpid(), time.Now().UnixNano())
	t.Cleanup(func() {
		_, err := pool.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		require.NoError(t, err)
	})
	auth, _ := authtest.New(t,
		authtest.WithConfig(func(c *authkit.Config) { c.Database.Schema = schema }),
		authtest.WithDeps(func(d *authkit.Deps) { d.Postgres = pool }))

	names := map[string]bool{}
	for range 3 {
		u := authtest.NewUser(t, auth)
		require.Regexp(t, generatedName, u.Username)
		require.Equal(t, u.Username+"@example.com", u.Email)
		names[u.Username] = true
	}

	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1")
	child.Env = append(os.Environ(), sharedSchemaEnv+"="+schema)
	out, err := child.CombinedOutput()
	require.NoError(t, err, "the child process: %s", out)
	var theirs []string
	for _, line := range strings.Split(string(out), "\n") {
		if generatedName.MatchString(line) {
			theirs = append(theirs, line)
		}
	}
	require.Len(t, theirs, 3, "the child process: %s", out)
	for _, name := range theirs {
		require.False(t, names[name], "%s created twice", name)
		names[name] = true
		_, err := auth.User(ctx, iam.UserByUsername(name))
		require.NoError(t, err, "the child created %s in the shared schema", name)
	}
}
