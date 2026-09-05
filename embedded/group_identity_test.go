package embedded

import (
	"context"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// orgGroupTestService builds a schema with one "org" persona (member role) over
// a scratch Postgres, seeded with containment and the root group.
func orgGroupTestService(t *testing.T) (*Client, *testdb.Postgres, context.Context) {
	t.Helper()
	pg := testdb.ScratchPostgres(t)
	ctx := context.Background()
	gs, err := BuildSchema(PersonaDef{
		Name: "org", Parent: RootPersona,
		Roles: []RoleDef{{Name: "member", Permissions: []string{"org:repo:read"}}},
	})
	if err != nil {
		t.Fatalf("BuildSchema: %v", err)
	}
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pg.Pool))
	svc.groupSchema = gs
	if err := svc.SeedPermissionGroupContainment(ctx); err != nil {
		t.Fatalf("SeedPermissionGroupContainment: %v", err)
	}
	if _, err := svc.EnsureRootGroup(ctx); err != nil {
		t.Fatalf("EnsureRootGroup: %v", err)
	}
	return svc, pg, ctx
}

func TestResolvedGroupIdentitySurvivesNamesAndDeletionRetries(t *testing.T) {
	svc, pg, ctx := orgGroupTestService(t)
	owner, other := insertBareUser(t, pg.Pool), insertBareUser(t, pg.Pool)
	group, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "org", InstanceSlug: "original", OwnerSubjectID: owner})
	require.NoError(t, err)
	resolved, err := svc.GroupInstanceForSlug(ctx, authkit.GroupRef{Persona: "org", Instance: "original"})
	require.NoError(t, err)
	require.Equal(t, group, resolved.ID)
	renamed := "renamed"
	_, renameErr := svc.UpdateGroupInstanceAs(ctx, owner, group, authkit.GroupInstanceUpdate{Slug: &renamed})
	require.NoError(t, renameErr)
	current, err := svc.GroupInstanceByID(ctx, group)
	require.NoError(t, err)
	require.Equal(t, "renamed", current.InstanceSlug)
	allowed, err := svc.CanOnGroup(ctx, authkit.UserSubject(owner), group, "org:repo:read")
	require.NoError(t, err)
	require.True(t, allowed)
	allowed, err = svc.CanOnGroup(ctx, authkit.UserSubject(other), group, "org:repo:read")
	require.NoError(t, err)
	require.False(t, allowed)

	// The host releases the canonical name but cannot shorten earlier rename
	// reservations. UUID-addressed retries never follow the newly claimed name.
	require.NoError(t, svc.DeleteGroupInstanceByID(ctx, group, DeletePermissionGroupOptions{ReleaseSlug: true}))
	replacement, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "org", InstanceSlug: "renamed", OwnerSubjectID: other})
	require.NoError(t, err)
	require.NotEqual(t, group, replacement)
	require.NoError(t, svc.DeleteGroupInstanceByID(ctx, group, DeletePermissionGroupOptions{ReleaseSlug: true}))
	_, err = svc.GroupInstanceByID(ctx, replacement)
	require.NoError(t, err)
	allowed, err = svc.CanOnGroup(ctx, authkit.UserSubject(owner), replacement, "org:repo:read")
	require.NoError(t, err)
	require.False(t, allowed)
	allowed, err = svc.CanOnGroup(ctx, authkit.UserSubject(other), replacement, "org:repo:read")
	require.NoError(t, err)
	require.True(t, allowed)
	allowed, err = svc.CanOnGroup(ctx, authkit.UserSubject(owner), group, "org:repo:read")
	require.NoError(t, err)
	require.False(t, allowed)
	_, err = svc.GroupInstanceForSlug(ctx, authkit.GroupRef{Persona: "org", Instance: "original"})
	require.ErrorIs(t, err, ErrGroupNotFound, "a retained reservation cannot forward to a dead group")
	_, err = svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "org", InstanceSlug: "original", OwnerSubjectID: other})
	require.Error(t, err, "deletion must preserve the old name's reservation")
	root, err := svc.EnsureRootGroup(ctx)
	require.NoError(t, err)
	require.ErrorIs(t, svc.DeleteGroupInstanceByID(ctx, root, DeletePermissionGroupOptions{ReleaseSlug: true}), authkit.ErrUnknownGroupPersona)
	_, err = svc.GroupInstanceByID(ctx, root)
	require.NoError(t, err)
}
