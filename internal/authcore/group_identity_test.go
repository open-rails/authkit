package authcore

import (
	"testing"

	"github.com/open-rails/authkit"
	"github.com/stretchr/testify/require"
)

func TestResolvedGroupIdentitySurvivesNamesAndDeletionRetries(t *testing.T) {
	svc, pg, ctx := inviteTestService(t, false)
	owner, other := insertBareUser(t, pg.Pool), insertBareUser(t, pg.Pool)
	group, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "org", InstanceSlug: "original", OwnerSubjectID: owner})
	require.NoError(t, err)
	resolved, err := svc.GroupInstanceForSlug(ctx, "org", "original")
	require.NoError(t, err)
	require.Equal(t, group, resolved.ID)
	require.NoError(t, svc.RenamePermissionGroupSlugAs(ctx, owner, "org", "original", "renamed"))
	current, err := svc.GroupInstanceByID(ctx, group)
	require.NoError(t, err)
	require.Equal(t, "renamed", current.InstanceSlug)
	allowed, err := svc.CanOnGroup(ctx, owner, SubjectKindUser, group, "org:repo:read")
	require.NoError(t, err)
	require.True(t, allowed)
	allowed, err = svc.CanOnGroup(ctx, other, SubjectKindUser, group, "org:repo:read")
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
	allowed, err = svc.CanOnGroup(ctx, owner, SubjectKindUser, replacement, "org:repo:read")
	require.NoError(t, err)
	require.False(t, allowed)
	allowed, err = svc.CanOnGroup(ctx, other, SubjectKindUser, replacement, "org:repo:read")
	require.NoError(t, err)
	require.True(t, allowed)
	allowed, err = svc.CanOnGroup(ctx, owner, SubjectKindUser, group, "org:repo:read")
	require.NoError(t, err)
	require.False(t, allowed)
	_, err = svc.GroupInstanceForSlug(ctx, "org", "original")
	require.ErrorIs(t, err, ErrGroupNotFound, "a retained reservation cannot forward to a dead group")
	_, err = svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "org", InstanceSlug: "original", OwnerSubjectID: other})
	require.Error(t, err, "deletion must preserve the old name's reservation")
	root, err := svc.EnsureRootGroup(ctx)
	require.NoError(t, err)
	require.ErrorIs(t, svc.DeleteGroupInstanceByID(ctx, root, DeletePermissionGroupOptions{ReleaseSlug: true}), authkit.ErrUnknownGroupPersona)
	_, err = svc.GroupInstanceByID(ctx, root)
	require.NoError(t, err)
}
