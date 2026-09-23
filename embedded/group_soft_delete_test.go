package embedded

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/verify"
	"github.com/open-rails/helpers/auth"
	"github.com/stretchr/testify/require"
)

func softDeleteRuntime(t *testing.T) (*Runtime, *pgxpool.Pool) {
	t.Helper()
	pg := testdb.ScratchPostgres(t)
	cfg := maintenanceConfig()
	cfg.Keys = KeysConfig{AllowEphemeralDevKeys: true}
	cfg.Token.ExpectedAudiences = []string{"test"}
	cfg.RBAC = []PersonaDef{{Name: RootPersona}, {Name: "channel", Parent: RootPersona, Roles: []RoleDef{{Name: "reader", Permissions: []string{"channel:posts:read"}}}}, {Name: "section", Parent: "channel"}}
	runtimeConfig := pg.Pool.Config()
	runtimeConfig.MaxConns = 1
	runtimePool, err := pgxpool.NewWithConfig(t.Context(), runtimeConfig)
	require.NoError(t, err)
	t.Cleanup(runtimePool.Close)
	rt, err := New(cfg, Deps{Postgres: runtimePool})
	require.NoError(t, err)
	t.Cleanup(rt.Close)
	return rt, pg.Pool
}

func TestSoftDeleteGroupRetainsStateAndReleasesOwner(t *testing.T) {
	rt, pool := softDeleteRuntime(t)
	ctx := t.Context()
	client := rt.Client()
	owner, err := client.CreateUser(ctx, "retained-owner@example.test", "retained-owner")
	require.NoError(t, err)
	peer, err := client.CreateUser(ctx, "active-owner@example.test", "active-owner")
	require.NoError(t, err)
	group := authkit.GroupRef{Persona: "channel", Instance: "retained"}
	id, err := client.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: group.Persona, InstanceSlug: group.Instance, OwnerSubjectID: owner.ID})
	require.NoError(t, err)
	child, err := client.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "section", InstanceSlug: "retained-child", ParentPersona: "channel", ParentInstanceSlug: group.Instance, OwnerSubjectID: owner.ID})
	require.NoError(t, err)
	active, err := client.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "channel", InstanceSlug: "still-active", OwnerSubjectID: peer.ID})
	require.NoError(t, err)
	key, token, err := client.MintAPIKeyWithOptions(ctx, group, authkit.APIKeyMintOptions{Name: "retained-key", Role: "reader", CreatedBy: owner.ID})
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodGet, "https://maintenance.test/channel", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	verifier := verify.NewVerifier().WithService(rt.engine).WithPermissionChecker(rt.engine, "https://maintenance.test")
	principal, err := verifier.AuthenticateRequest(ctx, request)
	require.NoError(t, err)
	checker := principal.(auth.PermissionChecker)
	scope := auth.Scope{Authority: "https://maintenance.test", ID: id}
	allowed, err := checker.Can(ctx, scope, "channel:posts:read")
	require.NoError(t, err)
	require.True(t, allowed)
	result, err := client.SoftDeleteUsers(ctx, []string{owner.ID})
	require.NoError(t, err)
	require.ErrorIs(t, result[0].Err, authkit.ErrCannotRemoveLastAdminRole)
	deleted, err := client.SoftDeleteGroupInstanceByID(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, deleted.DeletedAt)
	again, err := client.SoftDeleteGroupInstanceByID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, deleted.DeletedAt, again.DeletedAt)
	for _, gid := range []string{id, child} {
		descriptor, err := client.GroupInstanceByID(ctx, gid)
		require.NoError(t, err)
		require.Equal(t, deleted.DeletedAt, descriptor.DeletedAt)
		allowed, err := client.CanOnGroup(ctx, authkit.UserSubject(owner.ID), gid, "channel:posts:read")
		require.NoError(t, err)
		require.False(t, allowed)
	}
	allowed, err = checker.Can(ctx, scope, "channel:posts:read")
	require.NoError(t, err)
	require.False(t, allowed, "captured machine principal must observe retirement without another proof")
	_, err = verifier.AuthenticateRequest(ctx, request)
	require.Error(t, err, "retired group's API key is unusable on subsequent requests")
	_, err = client.GroupInstanceForSlug(ctx, group)
	require.ErrorIs(t, err, authkit.ErrGroupNotFound)
	require.ErrorIs(t, client.OperatorAssignGroupRole(ctx, group, authkit.UserSubject(peer.ID), "reader"), authkit.ErrGroupNotFound)
	_, err = client.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "section", InstanceSlug: "forbidden-child", ParentPersona: "channel", ParentInstanceSlug: group.Instance, OwnerSubjectID: owner.ID})
	require.Error(t, err)
	_, err = client.UpdateGroupInstanceAs(ctx, owner.ID, id, authkit.GroupInstanceUpdate{DisplayName: new("changed")})
	require.Error(t, err)
	_, _, err = client.MintAPIKeyWithOptions(ctx, group, authkit.APIKeyMintOptions{Name: "forbidden", Role: "reader"})
	require.Error(t, err)
	var roles, keys, names int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM profiles.group_user_roles WHERE permission_group_id=ANY($1::uuid[])", []string{id, child}).Scan(&roles))
	require.Equal(t, 2, roles)
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM profiles.api_keys WHERE id=$1::uuid", key.ID).Scan(&keys))
	require.Equal(t, 1, keys)
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM profiles.name_claims WHERE owner_id=ANY($1::uuid[]) AND canonical", []string{id, child}).Scan(&names))
	require.Equal(t, 2, names)
	result, err = client.SoftDeleteUsers(ctx, []string{owner.ID, peer.ID})
	require.NoError(t, err)
	require.NoError(t, result[0].Err)
	require.ErrorIs(t, result[1].Err, authkit.ErrCannotRemoveLastAdminRole, "active sibling still requires its owner")
	current, err := client.GroupInstanceByID(ctx, active)
	require.NoError(t, err)
	require.Nil(t, current.DeletedAt)
	root, err := client.GroupInstanceForSlug(ctx, authkit.RootGroup())
	require.NoError(t, err)
	_, err = client.SoftDeleteGroupInstanceByID(ctx, root.ID)
	require.Error(t, err)
	require.NoError(t, client.DeleteGroupInstanceByID(ctx, id, authkit.DeletePermissionGroupOptions{}))
	require.NoError(t, client.DeleteGroupInstanceByID(ctx, id, authkit.DeletePermissionGroupOptions{}))
	_, err = client.GroupInstanceByID(ctx, id)
	require.ErrorIs(t, err, authkit.ErrGroupNotFound)
}

func TestSoftDeleteGroupSerializesOwnerAccountDeletion(t *testing.T) {
	rt, _ := softDeleteRuntime(t)
	client := rt.Client()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for n := range 8 {
		owner, err := client.CreateUser(ctx, fmt.Sprintf("race-%d@example.test", n), fmt.Sprintf("retirerace%d", n))
		require.NoError(t, err)
		id, err := client.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "channel", InstanceSlug: fmt.Sprintf("race-%d", n), OwnerSubjectID: owner.ID})
		require.NoError(t, err)
		start := make(chan struct{})
		var wg sync.WaitGroup
		var retireErr, deleteErr error
		wg.Go(func() { <-start; _, retireErr = client.SoftDeleteGroupInstanceByID(ctx, id) })
		wg.Go(func() {
			<-start
			results, err := client.SoftDeleteUsers(ctx, []string{owner.ID})
			deleteErr = err
			if err == nil {
				deleteErr = results[0].Err
			}
		})
		close(start)
		wg.Wait()
		require.NoError(t, retireErr)
		if deleteErr != nil {
			require.ErrorIs(t, deleteErr, authkit.ErrCannotRemoveLastAdminRole)
		}
		results, err := client.SoftDeleteUsers(ctx, []string{owner.ID})
		require.NoError(t, err)
		require.NoError(t, results[0].Err)
		retained, err := client.GroupInstanceByID(ctx, id)
		require.NoError(t, err)
		require.NotNil(t, retained.DeletedAt)
	}
}

func TestSoftDeleteGroupRollsBackExternalOwnerLoss(t *testing.T) {
	rt, pool := softDeleteRuntime(t)
	client := rt.Client()
	ctx := t.Context()
	owner, err := client.CreateUser(ctx, "external-owner@example.test", "external-owner")
	require.NoError(t, err)
	controller, err := client.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "channel", InstanceSlug: "controller", OwnerSubjectID: owner.ID})
	require.NoError(t, err)
	survivor := authkit.GroupRef{Persona: "channel", Instance: "survivor"}
	survivorID, err := client.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: survivor.Persona, InstanceSlug: survivor.Instance})
	require.NoError(t, err)
	application, err := client.UpsertRemoteApplication(ctx, authkit.RemoteApplication{Slug: "retained-app", PermissionGroupID: controller, Issuer: "https://retained-app.example", JWKSURI: "https://retained-app.example/jwks", Mode: authkit.RemoteAppModeJWKS, Enabled: true})
	require.NoError(t, err)
	// Arrange a historical cross-control assignment that ordinary assignment APIs
	// already refuse. Retirement must not count this departing app as a replacement.
	_, err = pool.Exec(ctx, "INSERT INTO profiles.group_remote_application_roles(permission_group_id,remote_application_id,role) VALUES($1::uuid,$2::uuid,'owner')", survivorID, application.ID)
	require.NoError(t, err)
	_, err = client.SoftDeleteGroupInstanceByID(ctx, controller)
	require.ErrorIs(t, err, authkit.ErrCannotRemoveLastAdminRole)
	unchanged, err := client.GroupInstanceByID(ctx, controller)
	require.NoError(t, err)
	require.Nil(t, unchanged.DeletedAt, "failed retirement is atomic")
	require.NoError(t, client.OperatorAssignGroupRole(ctx, survivor, authkit.UserSubject(owner.ID), "owner"))
	_, err = client.SoftDeleteGroupInstanceByID(ctx, controller)
	require.NoError(t, err)
	_, err = client.GetRemoteApplication(ctx, application.Issuer)
	require.Error(t, err)
	_, err = client.ResolveRemoteApplicationAuthority(ctx, application.ID)
	require.Error(t, err)
	allowed, err := client.CanOnGroup(ctx, authkit.RemoteAppSubject(application.ID), survivorID, "channel:posts:read")
	require.NoError(t, err)
	require.False(t, allowed)
	application.Enabled = false
	_, err = client.UpsertRemoteApplication(ctx, *application)
	require.ErrorIs(t, err, authkit.ErrGroupNotFound, "retained application state cannot be rewritten")
}
