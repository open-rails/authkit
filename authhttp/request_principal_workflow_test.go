package authhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/helpers/auth"
	"github.com/stretchr/testify/require"
)

func TestRuntimeRequestPrincipalUsesLiveAuthority(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := instanceCreateTestConfig()
	client := newServerClient(t, cfg, pg.Pool)
	ctx := t.Context()
	group, err := client.EnsureRootGroup(ctx)
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
	allowed, err := checker.Can(ctx, scope, "root:resources:read")
	require.NoError(t, err)
	require.False(t, allowed)
	require.NoError(t, client.OperatorAssignGroupRole(ctx, authkit.RootGroup(), authkit.UserSubject(userID), "site-admin"))
	allowed, err = checker.Can(ctx, scope, "root:resources:read")
	require.NoError(t, err)
	require.True(t, allowed, "runtime must wire live authority without host glue")
	require.NoError(t, client.OperatorUnassignGroupRole(ctx, authkit.RootGroup(), authkit.UserSubject(userID), "site-admin"))
	allowed, err = checker.Can(ctx, scope, "root:resources:read")
	require.NoError(t, err)
	require.False(t, allowed, "same principal observes removal without reauthenticating")
}

func TestRetiredGroupRevokesNativeSessionAuthority(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := instanceCreateTestConfig()
	runtime := newServerClient(t, cfg, pg.Pool)
	service, err := newTestService(runtime, workflowHTTPConfig())
	require.NoError(t, err)
	t.Cleanup(service.Close)
	ctx := t.Context()
	client := runtime.Runtime.Client()
	owner, token := newInstanceTestUser(t, service, "retirednative")
	group := authkit.GroupRef{Persona: "org", Instance: "retained-native"}
	id, err := client.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: group.Persona, InstanceSlug: group.Instance, OwnerSubjectID: owner})
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodGet, "https://example.com/org/retained-native", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	principal, err := service.Verifier().AuthenticateRequest(ctx, request)
	require.NoError(t, err)
	checker := principal.(auth.PermissionChecker)
	scope := auth.Scope{Authority: cfg.Token.Issuer, ID: id}
	allowed, err := checker.Can(ctx, scope, "org:catalog:read")
	require.NoError(t, err)
	require.True(t, allowed)
	before, err := client.SoftDeleteUsers(ctx, []string{owner})
	require.NoError(t, err)
	require.ErrorIs(t, before[0].Err, authkit.ErrCannotRemoveLastAdminRole)
	descriptor, err := client.SoftDeleteGroupInstanceByID(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, descriptor.DeletedAt)
	allowed, err = checker.Can(ctx, scope, "org:catalog:read")
	require.NoError(t, err)
	require.False(t, allowed, "the same native principal loses group authority immediately")
	response := serveAuthJSON(service, http.MethodGet, "/org/retained-native", "", token)
	require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
	after, err := client.SoftDeleteUsers(ctx, []string{owner})
	require.NoError(t, err)
	require.NoError(t, after[0].Err)
	retained, err := client.GroupInstanceByID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, descriptor.DeletedAt, retained.DeletedAt)
}
