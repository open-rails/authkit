package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/helpers/auth"
	"github.com/stretchr/testify/require"
)

func TestRuntimeRequestPrincipalUsesLiveAuthority(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := orgTestConfig()
	client := newServerClient(t, cfg, pg.Pool)
	ctx := t.Context()
	group, err := client.ensureRootGroup(ctx)
	require.NoError(t, err)
	service, err := newTestService(client, workflowHTTPConfig())
	require.NoError(t, err)
	t.Cleanup(service.Close)
	userID, token := newInstanceTestUser(t, service, "neutralprincipal")
	req := httptest.NewRequest(http.MethodGet, "https://resource.example/account", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	principal, err := service.Verifier().AuthenticateRequest(ctx, req)
	require.NoError(t, err)
	require.Equal(t, userID, principal.Identity().Subject)
	checker := principal.(auth.PermissionChecker)
	scope := auth.Scope{Authority: cfg.Token.Issuer, ID: group}
	allowed, err := checker.Can(ctx, scope, iam.PermRootUsersRead)
	require.NoError(t, err)
	require.False(t, allowed)
	grantRole(t, client, iam.RootGroup(), iam.UserSubject(userID), "site-admin")
	allowed, err = checker.Can(ctx, scope, iam.PermRootUsersRead)
	require.NoError(t, err)
	require.True(t, allowed, "runtime must wire live authority without host glue")
	revokeRole(t, client, iam.RootGroup(), iam.UserSubject(userID), "site-admin")
	allowed, err = checker.Can(ctx, scope, iam.PermRootUsersRead)
	require.NoError(t, err)
	require.False(t, allowed, "same principal observes removal without reauthenticating")
}

func TestRetiredGroupRevokesNativeSessionAuthority(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := orgTestConfig()
	runtime := newServerClient(t, cfg, pg.Pool)
	service, err := newTestService(runtime, workflowHTTPConfig())
	require.NoError(t, err)
	t.Cleanup(service.Close)
	ctx := t.Context()
	client := runtime
	owner, token := newInstanceTestUser(t, service, "retirednative")
	id, err := seedGroup(ctx, client, "org", owner)
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodGet, "https://example.com/org/"+id, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	principal, err := service.Verifier().AuthenticateRequest(ctx, request)
	require.NoError(t, err)
	checker := principal.(auth.PermissionChecker)
	scope := auth.Scope{Authority: cfg.Token.Issuer, ID: id}
	allowed, err := checker.Can(ctx, scope, "org:catalog:read")
	require.NoError(t, err)
	require.True(t, allowed)
	before, err := client.DeleteUsers(ctx, iam.SystemActor(), []string{owner})
	require.NoError(t, err)
	require.ErrorIs(t, before[0].Err, iam.ErrLastOwner)
	require.NoError(t, client.DeleteGroup(ctx, iam.GroupByID(id), nil))
	descriptor, err := client.Group(ctx, iam.GroupByID(id))
	require.NoError(t, err)
	require.NotNil(t, descriptor.DeletedAt)
	allowed, err = checker.Can(ctx, scope, "org:catalog:read")
	require.NoError(t, err)
	require.False(t, allowed, "the same native principal loses group authority immediately")
	response := serveAuthJSON(service, http.MethodGet, "/groups/"+id+"/members", "", token)
	require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
	after, err := client.DeleteUsers(ctx, iam.SystemActor(), []string{owner})
	require.NoError(t, err)
	require.NoError(t, after[0].Err)
	retained, err := client.Group(ctx, iam.GroupByID(id))
	require.NoError(t, err)
	require.Equal(t, descriptor.DeletedAt, retained.DeletedAt)
}
