package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/verify"
	"github.com/open-rails/helpers/auth"
	"github.com/stretchr/testify/require"
)

func softDeleteRuntime(t *testing.T) (*Engine, *pgxpool.Pool) {
	t.Helper()
	pg := testdb.ScratchPostgres(t)
	cfg := maintenanceConfig()
	cfg.Keys = KeysConfig{AllowEphemeralDevKeys: true}
	cfg.Token.ExpectedAudiences = []string{"test"}
	cfg.Roles = RoleConfig{
		Personas: map[string]Persona{"channel": {Permissions: []string{"channel:posts:read"}, APIKeys: true}},
		Roles:    []Role{{Persona: "channel", Name: "reader", Permissions: []string{"channel:posts:read"}}},
	}
	runtimeConfig := pg.Pool.Config()
	runtimeConfig.MaxConns = 1
	runtimePool, err := pgxpool.NewWithConfig(t.Context(), runtimeConfig)
	require.NoError(t, err)
	t.Cleanup(runtimePool.Close)
	rt, err := New(context.Background(), cfg, Deps{Postgres: runtimePool})
	require.NoError(t, err)
	t.Cleanup(rt.Close)
	return rt, pg.Pool
}

func TestSoftDeleteGroupRetainsStateAndReleasesOwner(t *testing.T) {
	rt, pool := softDeleteRuntime(t)
	ctx := t.Context()
	client := rt
	owner, err := client.createUser(ctx, "retained-owner@example.test", "retained-owner")
	require.NoError(t, err)
	peer, err := client.createUser(ctx, "active-owner@example.test", "active-owner")
	require.NoError(t, err)
	id, err := seedGroup(ctx, client, ident.Persona("channel"), owner.ID)
	require.NoError(t, err)
	group := iam.GroupByID(id)
	active, err := seedGroup(ctx, client, ident.Persona("channel"), peer.ID)
	require.NoError(t, err)
	key, token, err := client.MintAPIKey(ctx, iam.UserActor(owner.ID), group, iam.NewAPIKey{Name: "retained-key", Role: mustRole("channel:reader")})
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodGet, "https://maintenance.test/channel", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	verifier := verify.NewVerifier().WithService(rt).WithPermissionChecker(rt, "https://maintenance.test")
	principal, err := verifier.AuthenticateRequest(ctx, request)
	require.NoError(t, err)
	checker := principal.(auth.PermissionChecker)
	scope := auth.Scope{Authority: "https://maintenance.test", ID: id}
	allowed, err := checker.Can(ctx, scope, "channel:posts:read")
	require.NoError(t, err)
	require.True(t, allowed)
	result, err := client.DeleteUsers(ctx, iam.SystemActor(), []string{owner.ID})
	require.NoError(t, err)
	require.ErrorIs(t, result[0].Err, iam.ErrLastOwner)
	require.NoError(t, client.DeleteGroup(ctx, group, nil))
	deleted, err := client.Group(ctx, group)
	require.NoError(t, err)
	require.NotNil(t, deleted.DeletedAt)
	require.NoError(t, client.DeleteGroup(ctx, group, nil), "deleting a deleted group is a no-op")
	descriptor, err := client.Group(ctx, iam.GroupByID(id))
	require.NoError(t, err)
	require.Equal(t, deleted.DeletedAt, descriptor.DeletedAt)
	allowed, err = client.Can(ctx, iam.UserActor(owner.ID), iam.GroupByID(id), ident.Perm("channel:posts:read"))
	require.NoError(t, err)
	require.False(t, allowed)
	allowed, err = checker.Can(ctx, scope, "channel:posts:read")
	require.NoError(t, err)
	require.False(t, allowed, "captured machine principal must observe retirement without another proof")
	_, err = verifier.AuthenticateRequest(ctx, request)
	require.Error(t, err, "retired group's API key is unusable on subsequent requests")
	require.ErrorIs(t, assignRole(ctx, client, iam.SystemActor(), group, iam.UserSubject(peer.ID), "reader"), iam.ErrGroupNotFound)
	_, _, err = client.MintAPIKey(ctx, iam.SystemActor(), group, iam.NewAPIKey{Name: "forbidden", Role: mustRole("channel:reader")})
	require.ErrorIs(t, err, iam.ErrGroupNotFound)
	var roles, keys int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM profiles.group_user_roles WHERE permission_group_id=$1::uuid", id).Scan(&roles))
	require.Equal(t, 1, roles)
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM profiles.api_keys WHERE id=$1::uuid", key.ID).Scan(&keys))
	require.Equal(t, 1, keys)
	result, err = client.DeleteUsers(ctx, iam.SystemActor(), []string{owner.ID, peer.ID})
	require.NoError(t, err)
	require.NoError(t, result[0].Err)
	require.ErrorIs(t, result[1].Err, iam.ErrLastOwner, "active sibling still requires its owner")
	current, err := client.Group(ctx, iam.GroupByID(active))
	require.NoError(t, err)
	require.Nil(t, current.DeletedAt)
	root, err := client.Group(ctx, iam.RootGroup())
	require.NoError(t, err)
	require.Error(t, client.DeleteGroup(ctx, iam.GroupByID(root.ID), nil))
	require.NoError(t, client.PurgeGroup(ctx, iam.GroupByID(id), nil))
	require.NoError(t, client.PurgeGroup(ctx, iam.GroupByID(id), nil))
	_, err = client.Group(ctx, iam.GroupByID(id))
	require.ErrorIs(t, err, iam.ErrGroupNotFound)
}

func TestSoftDeleteGroupSerializesOwnerAccountDeletion(t *testing.T) {
	rt, _ := softDeleteRuntime(t)
	client := rt
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for n := range 8 {
		owner, err := client.createUser(ctx, fmt.Sprintf("race-%d@example.test", n), fmt.Sprintf("retirerace%d", n))
		require.NoError(t, err)
		id, err := seedGroup(ctx, client, ident.Persona("channel"), owner.ID)
		require.NoError(t, err)
		start := make(chan struct{})
		var wg sync.WaitGroup
		var retireErr, deleteErr error
		wg.Go(func() { <-start; retireErr = client.DeleteGroup(ctx, iam.GroupByID(id), nil) })
		wg.Go(func() {
			<-start
			results, err := client.DeleteUsers(ctx, iam.SystemActor(), []string{owner.ID})
			deleteErr = err
			if err == nil {
				deleteErr = results[0].Err
			}
		})
		close(start)
		wg.Wait()
		require.NoError(t, retireErr)
		if deleteErr != nil {
			require.ErrorIs(t, deleteErr, iam.ErrLastOwner)
		}
		results, err := client.DeleteUsers(ctx, iam.SystemActor(), []string{owner.ID})
		require.NoError(t, err)
		require.NoError(t, results[0].Err)
		retained, err := client.Group(ctx, iam.GroupByID(id))
		require.NoError(t, err)
		require.NotNil(t, retained.DeletedAt)
	}
}

func TestSoftDeleteGroupRollsBackExternalOwnerLoss(t *testing.T) {
	rt, pool := softDeleteRuntime(t)
	client := rt
	ctx := t.Context()
	owner, err := client.createUser(ctx, "external-owner@example.test", "external-owner")
	require.NoError(t, err)
	controller, err := seedGroup(ctx, client, ident.Persona("channel"), owner.ID)
	require.NoError(t, err)
	survivorID, err := seedGroup(ctx, client, ident.Persona("channel"), "")
	require.NoError(t, err)
	survivor := iam.GroupByID(survivorID)
	application, err := client.UpsertRemoteApplication(ctx, iam.SystemActor(), iam.GroupByID(controller), iam.RemoteApplication{Slug: "retained-app", Issuer: "https://retained-app.example", JWKSURI: "https://retained-app.example/jwks", Mode: iam.RemoteApplicationModeJWKS, Enabled: true})
	require.NoError(t, err)
	// Arrange a historical cross-control assignment that ordinary assignment APIs
	// already refuse. Retirement must not count this departing app as a replacement.
	_, err = pool.Exec(ctx, "INSERT INTO profiles.group_remote_application_roles(permission_group_id,remote_application_id,role) VALUES($1::uuid,$2::uuid,'owner')", survivorID, application.ID)
	require.NoError(t, err)
	require.ErrorIs(t, client.DeleteGroup(ctx, iam.GroupByID(controller), nil), iam.ErrLastOwner)
	unchanged, err := client.Group(ctx, iam.GroupByID(controller))
	require.NoError(t, err)
	require.Nil(t, unchanged.DeletedAt, "failed retirement is atomic")
	grantRole(t, client, survivor, iam.UserSubject(owner.ID), "owner")
	require.NoError(t, client.DeleteGroup(ctx, iam.GroupByID(controller), nil))
	_, err = client.GetRemoteApplication(ctx, application.Issuer)
	require.Error(t, err)
	_, err = client.ResolveRemoteApplicationAuthority(ctx, application.ID)
	require.Error(t, err)
	allowed, err := client.Can(ctx, iam.RemoteApplicationActor(application.ID), iam.GroupByID(survivorID), ident.Perm("channel:posts:read"))
	require.NoError(t, err)
	require.False(t, allowed)
	application.Enabled = false
	_, err = client.UpsertRemoteApplication(ctx, iam.SystemActor(), iam.GroupByID(application.PermissionGroupID), *application)
	require.ErrorIs(t, err, iam.ErrGroupNotFound, "retained application state cannot be rewritten")
}
