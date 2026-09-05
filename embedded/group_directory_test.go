package embedded_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authkitmigrate"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestGroupDirectoryReusesAliasesAndCustomSchema(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := context.Background()
	const schema = "directory_custom"
	_, err := authkitmigrate.New(pg.Pool, &authkitmigrate.Config{Schema: schema}).Migrate(ctx)
	require.NoError(t, err)
	client, err := embedded.New(embedded.Config{Schema: schema, Keys: embedded.KeysConfig{VerifyOnly: true}, Token: embedded.TokenConfig{Issuer: "https://auth.test", IssuedAudiences: []string{"test"}}, RBAC: []embedded.PersonaDef{{Name: "merchant", Parent: embedded.RootPersona}}}, pg.Pool)
	require.NoError(t, err)
	require.NoError(t, client.SeedPermissionGroupContainment(ctx))
	_, err = client.EnsureRootGroup(ctx)
	require.NoError(t, err)
	owner, err := client.CreateUser(ctx, "directory@example.test", "directory_owner")
	require.NoError(t, err)
	id, err := client.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "original", OwnerSubjectID: owner.ID})
	require.NoError(t, err)
	renamed := "renamed"
	_, err = client.UpdateGroupInstanceAs(ctx, owner.ID, id, authkit.GroupInstanceUpdate{Slug: &renamed})
	require.NoError(t, err)
	directory, err := embedded.NewGroupDirectory(pg.Pool, schema)
	require.NoError(t, err)
	for _, name := range []string{"original", "renamed"} {
		group, err := directory.GroupInstanceForSlug(ctx, "merchant", name)
		require.NoError(t, err)
		require.Equal(t, id, group.ID)
		require.Equal(t, "renamed", group.InstanceSlug)
	}
	direct, err := directory.GroupInstanceByID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, id, direct.ID)
	_, err = directory.GroupInstanceForSlug(ctx, "merchant", "missing")
	require.ErrorIs(t, err, authkit.ErrGroupNotFound)
	for _, name := range []string{"name-a", "name-b"} {
		_, err := client.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: name})
		require.NoError(t, err)
	}
	page, err := directory.SearchGroupInstances(ctx, "merchant", "NAME", "", "", 1)
	require.NoError(t, err)
	require.Len(t, page, 1)
	require.Equal(t, "name-a", page[0].InstanceSlug)
	page, err = directory.SearchGroupInstances(ctx, "merchant", "name", page[0].InstanceSlug, page[0].ID, 1)
	require.NoError(t, err)
	require.Len(t, page, 1)
	require.Equal(t, "name-b", page[0].InstanceSlug)
	page, err = directory.SearchGroupInstances(ctx, "merchant", "name", page[0].InstanceSlug, page[0].ID, 1)
	require.NoError(t, err)
	require.Len(t, page, 1)
	require.Equal(t, "renamed", page[0].InstanceSlug)
	page, err = directory.SearchGroupInstances(ctx, "merchant", "original", "", "", 0)
	require.NoError(t, err)
	require.Empty(t, page, "a live alias is not a canonical search result")
	page, err = directory.SearchGroupInstances(ctx, "merchant", "%", "", "", 0)
	require.NoError(t, err)
	require.Empty(t, page, "search is literal, not a wildcard expression")
	_, err = directory.SearchGroupInstances(ctx, "merchant", "", "name-a", "", 1)
	require.Error(t, err)
	_, err = directory.SearchGroupInstances(ctx, "merchant", "", "", "", 201)
	require.Error(t, err)
	_, err = pg.Pool.Exec(ctx, "UPDATE "+pgx.Identifier{schema, "name_claims"}.Sanitize()+" SET expires_at=now()-interval '1 second' WHERE name='original' AND owner_id=$1::uuid", id)
	require.NoError(t, err)
	_, err = directory.GroupInstanceForSlug(ctx, "merchant", "original")
	require.ErrorIs(t, err, authkit.ErrGroupNotFound)
	defaults, err := embedded.NewGroupDirectory(pg.Pool, "")
	require.NoError(t, err)
	_, err = defaults.GroupInstanceByID(ctx, id)
	require.ErrorIs(t, err, authkit.ErrGroupNotFound)
	// Read-only construction cannot create a missing schema as a side effect.
	empty, err := embedded.NewGroupDirectory(pg.Pool, "directory_missing")
	require.NoError(t, err)
	_, err = empty.GroupInstanceForSlug(ctx, "merchant", "missing")
	require.Error(t, err)
	var exists bool
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='directory_missing')`).Scan(&exists))
	require.False(t, exists)
	_, err = embedded.NewGroupDirectory(nil, "")
	require.Error(t, err)
	_, err = embedded.NewGroupDirectory(pg.Pool, "unsafe.schema")
	require.Error(t, err)
}
