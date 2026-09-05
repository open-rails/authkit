package embedded_test

import (
	"context"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestResolvedGroupContextKeepsEmbeddedMutationsOnAuthorizedUUID(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := context.Background()
	zero := time.Duration(0)
	client, err := embedded.New(embedded.Config{Keys: embedded.KeysConfig{VerifyOnly: true}, Token: embedded.TokenConfig{Issuer: "https://auth.test", IssuedAudiences: []string{"test"}}, Naming: authkit.NamingConfig{RenameInterval: &zero, FormerNames: authkit.FormerNameRetentionConfig{Mode: authkit.FormerNamesImmediate}}, RBAC: []embedded.PersonaDef{{Name: "merchant", Parent: embedded.RootPersona, Capabilities: embedded.PersonaCapabilities{APIKeys: true}, Roles: []embedded.RoleDef{{Name: "reader", Permissions: []string{"merchant:catalog:read"}}}}}}, embedded.Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	require.NoError(t, client.SeedPermissionGroupContainment(ctx))
	_, err = client.EnsureRootGroup(ctx)
	require.NoError(t, err)
	owner, err := client.CreateUser(ctx, "owner@example.test", "owner")
	require.NoError(t, err)
	stranger, err := client.CreateUser(ctx, "stranger@example.test", "stranger")
	require.NoError(t, err)
	member, err := client.CreateUser(ctx, "member@example.test", "member")
	require.NoError(t, err)
	original, err := client.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "handle", OwnerSubjectID: owner.ID})
	require.NoError(t, err)
	captured, err := client.GroupInstanceForSlug(ctx, "merchant", "handle")
	require.NoError(t, err)
	allowed, err := client.CanOnGroup(ctx, owner.ID, embedded.SubjectKindUser, captured.ID, "merchant:members:manage")
	require.NoError(t, err)
	require.True(t, allowed)
	bound := embedded.WithResolvedGroup(ctx, captured, "handle")
	moved := "moved"
	_, err = client.UpdateGroupInstanceAs(ctx, owner.ID, captured.ID, authkit.GroupInstanceUpdate{Slug: &moved})
	require.NoError(t, err)
	replacement, err := client.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "handle", OwnerSubjectID: stranger.ID})
	require.NoError(t, err)
	require.NotEqual(t, original, replacement)
	require.NoError(t, client.AssignGroupRoleAs(bound, owner.ID, "merchant", "handle", member.ID, embedded.SubjectKindUser, "reader"))
	require.ErrorIs(t, client.AssignGroupRoleAs(ctx, owner.ID, "merchant", "handle", member.ID, embedded.SubjectKindUser, "reader"), authkit.ErrInsufficientRoleAuthority)
	members, err := client.ListGroupMembers(ctx, "merchant", "moved")
	require.NoError(t, err)
	require.Contains(t, members, authkit.GroupMember{SubjectID: member.ID, SubjectKind: embedded.SubjectKindUser, Role: "reader"})
	members, err = client.ListGroupMembers(ctx, "merchant", "handle")
	require.NoError(t, err)
	require.NotContains(t, members, authkit.GroupMember{SubjectID: member.ID, SubjectKind: embedded.SubjectKindUser, Role: "reader"})
	_, _, err = client.MintAPIKeyWithOptions(bound, "merchant", "handle", authkit.APIKeyMintOptions{Name: "captured", Role: "reader", CreatedBy: owner.ID})
	require.NoError(t, err)
	keys, err := client.ListAPIKeys(ctx, "merchant", "moved")
	require.NoError(t, err)
	require.Len(t, keys, 1)
	keys, err = client.ListAPIKeys(ctx, "merchant", "handle")
	require.NoError(t, err)
	require.Empty(t, keys)
	require.NoError(t, client.UnassignGroupRoleAs(bound, owner.ID, "merchant", "handle", member.ID, embedded.SubjectKindUser, "reader"))
	members, err = client.ListGroupMembers(ctx, "merchant", "moved")
	require.NoError(t, err)
	require.NotContains(t, members, authkit.GroupMember{SubjectID: member.ID, SubjectKind: embedded.SubjectKindUser, Role: "reader"})
	require.NoError(t, client.DeletePermissionGroup(bound, "merchant", "handle", authkit.DeletePermissionGroupOptions{ReleaseSlug: true}))
	require.NoError(t, client.DeleteGroupInstanceByID(ctx, captured.ID, authkit.DeletePermissionGroupOptions{ReleaseSlug: true}))
	_, err = client.ListGroupMembers(bound, "merchant", "handle")
	require.ErrorIs(t, err, authkit.ErrGroupNotFound)
	stillLive, err := client.GroupInstanceByID(ctx, replacement)
	require.NoError(t, err)
	require.Equal(t, replacement, stillLive.ID)
}
