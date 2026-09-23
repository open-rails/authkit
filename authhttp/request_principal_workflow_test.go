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
