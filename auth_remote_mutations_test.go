package authkit_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/remote"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/keys"
	"github.com/stretchr/testify/require"
)

func TestRemoteMutationActorIsOnlyAPrecondition(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := testConfig(t)
	cfg.HTTP = testHTTPConfig()
	cfg.TwoFactor.Mode = iam.TwoFactorDisabled
	cfg.Roles = authkit.NewRoles(authkit.OAuthClients, authkit.APIKeys, authkit.CustomRoles, authkit.RemoteApplications)
	managerRole := cfg.Roles.Root.Role("client-manager", cfg.Roles.Root.Credentials.Manage, cfg.Roles.Root.Credentials.Read, cfg.Roles.Root.Roles.Manage, cfg.Roles.Root.Members.Read)
	readerRole := cfg.Roles.Root.Role("client-reader", cfg.Roles.Root.Credentials.Read)
	native := newPublicRuntime(t, cfg, pg.Pool)
	t.Cleanup(func() { _ = native.Close(t.Context()) })
	manager, reader := authtest.NewUser(t, native), authtest.NewUser(t, native)
	_, err := native.SetGroupRole(t.Context(), iam.SystemIdentity(), iam.RootGroup(), iam.UserSubject(manager.ID), managerRole)
	require.NoError(t, err)
	_, err = native.SetGroupRole(t.Context(), iam.SystemIdentity(), iam.RootGroup(), iam.UserSubject(reader.ID), readerRole)
	require.NoError(t, err)
	managerToken := authtest.SignIn(t, native, manager).AccessToken
	readerToken := authtest.SignIn(t, native, reader).AccessToken
	server := httptest.NewServer(native.Handler())
	t.Cleanup(server.Close)
	connect := func(token string) (*remote.Client, auth.Identity) {
		c, err := remote.New(remote.Config{BaseURL: server.URL + "/api/v1", HTTPClient: server.Client(), Headers: http.Header{"Authorization": []string{"Bearer " + token}}})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodGet, server.URL+"/api/v1/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		verified, err := native.AuthenticateRequest(t.Context(), req)
		require.NoError(t, err)
		return c, verified.Identity()
	}
	transport, actor := connect(managerToken)
	readonly, readActor := connect(readerToken)
	input := iam.NewOAuthClient{ClientName: "Remote mutation", RedirectURIs: []string{"https://example.test/callback"}, TokenEndpointAuthMethod: iam.OAuthClientSecretBasic, Scope: "openid"}
	for _, field := range []string{"subject", "credential", "invoker", "tenant"} {
		t.Run("wrong_"+field, func(t *testing.T) {
			wrong := actor
			switch field {
			case "subject":
				wrong.Subject = reader.ID
			case "credential":
				wrong.Credential.ID = "another-credential"
			case "invoker":
				wrong.Invoker.ID = reader.ID
			case "tenant":
				wrong.TenantID = iam.NewTenantID().String()
			}
			_, err := transport.CreateGroupOAuthClient(t.Context(), wrong, iam.RootGroup(), input)
			requireEventErrorCode(t, err, "forbidden")
		})
	}
	// The new route requires the constraint; it cannot act as an ordinary route.
	body, err := json.Marshal(input)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/operations/groups/root/oauth-clients", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+managerToken)
	req.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, response.StatusCode)
	response.Body.Close()
	// Old deployments have no constrained-operation routes. Never retry the
	// ordinary path after a 404: that path cannot enforce the expected actor.
	oldServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/operations/") {
			http.NotFound(w, r)
			return
		}
		native.Handler().ServeHTTP(w, r)
	}))
	defer oldServer.Close()
	oldClient, err := remote.New(remote.Config{BaseURL: oldServer.URL + "/api/v1", HTTPClient: oldServer.Client(), Headers: http.Header{"Authorization": []string{"Bearer " + managerToken}}})
	require.NoError(t, err)
	_, err = oldClient.CreateGroupOAuthClient(t.Context(), actor, iam.RootGroup(), input)
	require.ErrorIs(t, err, remote.ErrOperationProtocolUnsupported)
	refusal, ok := iam.AsError(err)
	require.True(t, ok)
	require.Equal(t, http.StatusNotFound, refusal.Status())
	before, err := native.GroupOAuthClients(t.Context(), iam.RootGroup())
	require.NoError(t, err)
	require.Empty(t, before)
	// Even copying a manager's in-process credential state grants no HTTP power.
	forged := readActor
	forged.Credential = forged.Credential.WithState(actor.Credential.State())
	_, err = readonly.CreateGroupOAuthClient(t.Context(), forged, iam.RootGroup(), input)
	requireEventErrorCode(t, err, "forbidden")
	created, err := transport.CreateGroupOAuthClient(t.Context(), actor, iam.RootGroup(), input)
	require.NoError(t, err)
	require.NotNil(t, created.ClientSecret)
	stored, err := native.GroupOAuthClient(t.Context(), iam.RootGroup(), created.ClientID)
	require.NoError(t, err)
	require.Equal(t, input.ClientName, stored.ClientName)
	name := "Updated remotely"
	updated, err := transport.UpdateGroupOAuthClient(t.Context(), actor, iam.RootGroup(), created.ClientID, iam.OAuthClientUpdate{ClientName: &name})
	require.NoError(t, err)
	require.Equal(t, name, updated.ClientName)
	secret, err := transport.RotateGroupOAuthClientSecret(t.Context(), actor, iam.RootGroup(), created.ClientID)
	require.NoError(t, err)
	require.NotEmpty(t, secret)
	require.NotEqual(t, *created.ClientSecret, secret)
	// Group role and API-key mutations use the same constrained actor protocol.
	role, err := transport.CreateGroupRole(t.Context(), actor, iam.RootGroup(), iam.NewGroupRole{Name: "remote-reader", Permissions: []iam.Perm{cfg.Roles.Root.Credentials.Read}})
	require.NoError(t, err)
	role, err = transport.UpdateGroupRole(t.Context(), actor, iam.RootGroup(), role.Name, iam.GroupRoleUpdate{Permissions: []iam.Perm{cfg.Roles.Root.Credentials.Read, cfg.Roles.Root.Members.Read}})
	require.NoError(t, err)
	storedRole, err := native.GroupRole(t.Context(), iam.RootGroup(), role.Name)
	require.NoError(t, err)
	assertWireEqual(t, storedRole, role)
	key, err := transport.CreateAPIKey(t.Context(), actor, iam.RootGroup(), iam.NewAPIKey{Name: "Remote-created", Role: readerRole})
	require.NoError(t, err)
	require.NotEmpty(t, key.Secret)
	_, err = native.ResolveAPIKey(t.Context(), key.Secret)
	require.NoError(t, err)
	require.NoError(t, transport.RevokeAPIKey(t.Context(), actor, iam.RootGroup(), key.APIKey.ID))
	_, err = native.ResolveAPIKey(t.Context(), key.Secret)
	require.ErrorIs(t, err, iam.ErrAPIKeyRevoked)
	missing := uuid.NewString()
	nativeErr := native.RevokeAPIKey(t.Context(), iam.SystemIdentity(), iam.RootGroup(), missing)
	require.ErrorIs(t, nativeErr, iam.ErrAPIKeyNotFound)
	require.ErrorIs(t, transport.RevokeAPIKey(t.Context(), actor, iam.RootGroup(), missing), iam.ErrAPIKeyNotFound)
	require.NoError(t, transport.DeleteGroupRole(t.Context(), actor, iam.RootGroup(), role.Name))
	jwk := keys.PublicJWK(testKeys().Active.Public(), "delete-remote", "")
	app, err := native.UpsertRemoteApplication(t.Context(), actor, iam.RootGroup(), iam.RemoteApplication{Issuer: "https://delete-remote.example.test", Enabled: true, PublicKeys: []iam.RemoteApplicationKey{{JWK: &jwk}}})
	require.NoError(t, err)
	require.NoError(t, transport.DeleteRemoteApplication(t.Context(), actor, iam.RootGroup(), app.ID))
	require.ErrorIs(t, transport.DeleteRemoteApplication(t.Context(), actor, iam.RootGroup(), app.ID), iam.ErrRemoteApplicationNotFound)
	// Native transaction options are refused before an HTTP request, not ignored.
	tx, err := pg.Pool.Begin(t.Context())
	require.NoError(t, err)
	defer tx.Rollback(t.Context())
	_, err = transport.CreateGroupOAuthClient(t.Context(), actor, iam.RootGroup(), input, authkit.InTx(tx))
	requireEventErrorCode(t, err, "invalid_request")
	// The existing freshness gate remains authoritative after actor matching.
	_, err = pg.Pool.Exec(t.Context(), "UPDATE refresh_sessions SET last_authenticated_at=clock_timestamp()-interval '1 hour' WHERE user_id=$1", manager.ID)
	require.NoError(t, err)
	claims, err := native.Verify(t.Context(), managerToken)
	require.NoError(t, err)
	stale, err := native.MintAccessToken(t.Context(), manager.ID, iam.AccessTokenOptions{SessionID: claims.SessionID})
	require.NoError(t, err)
	staleTransport, staleActor := connect(stale.Value)
	err = staleTransport.DeleteGroupOAuthClient(t.Context(), staleActor, iam.RootGroup(), created.ClientID)
	requireEventErrorCode(t, err, "step_up_required")
	_, err = pg.Pool.Exec(t.Context(), "UPDATE refresh_sessions SET last_authenticated_at=clock_timestamp() WHERE user_id=$1", manager.ID)
	require.NoError(t, err)
	require.NoError(t, transport.DeleteGroupOAuthClient(t.Context(), actor, iam.RootGroup(), created.ClientID))
	after, err := native.GroupOAuthClients(t.Context(), iam.RootGroup())
	require.NoError(t, err)
	require.Empty(t, after)
}
