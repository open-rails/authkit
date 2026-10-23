package authkit_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ops"
	"github.com/open-rails/authkit/internal/remote"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/wireform"
	"github.com/open-rails/authkit/keys"
	"github.com/stretchr/testify/require"
)

func TestRemoteReadOperationSignatures(t *testing.T) {
	native, transport := reflect.TypeFor[ops.Operations](), reflect.TypeFor[*remote.Client]()
	for m := range transport.Methods() {
		op, ok := native.MethodByName(m.Name)
		require.True(t, ok, m.Name)
		require.Equal(t, op.Type.NumIn()+1, m.Type.NumIn(), m.Name)
		for i := range op.Type.NumIn() {
			require.Equal(t, op.Type.In(i), m.Type.In(i+1), m.Name)
		}
		require.Equal(t, op.Type.NumOut(), m.Type.NumOut(), m.Name)
		for i := range op.Type.NumOut() {
			require.Equal(t, op.Type.Out(i), m.Type.Out(i), m.Name)
		}
	}
}

func assertWireEqual(t *testing.T, want, got any) {
	t.Helper()
	a, err := json.Marshal(wireform.Of(want))
	require.NoError(t, err)
	b, err := json.Marshal(wireform.Of(got))
	require.NoError(t, err)
	require.JSONEq(t, string(a), string(b))
}

func TestRemoteDomainReadsUseRealAuthorization(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := testConfig(t)
	cfg.HTTP = testHTTPConfig()
	cfg.TwoFactor.Mode = iam.TwoFactorDisabled
	cfg.Roles = authkit.NewRoles(authkit.OAuthClients, authkit.APIKeys, authkit.RemoteApplications, authkit.CustomRoles)
	readRole := cfg.Roles.Root.Role("read-api", cfg.Roles.Root.Users.Read, cfg.Roles.Root.Members.Read, cfg.Roles.Root.Credentials.Read, cfg.Roles.Root.Roles.Read)
	deps := testDeps(pg.Pool)
	var entitlementCalls atomic.Int32
	deps.Entitlements = func(ctx context.Context, ids []string) (map[string][]string, error) {
		entitlementCalls.Add(1)
		out := make(map[string][]string, len(ids))
		for _, id := range ids {
			out[id] = []string{"sample"}
		}
		return out, nil
	}
	native, err := authkit.New(t.Context(), cfg, deps)
	require.NoError(t, err)
	t.Cleanup(func() { _ = native.Close(t.Context()) })
	user := authtest.NewUser(t, native)
	_, err = native.SetGroupRole(t.Context(), iam.SystemIdentity(), iam.RootGroup(), iam.UserSubject(user.ID), readRole)
	require.NoError(t, err)
	target := authtest.NewUser(t, native)
	token := authtest.SignIn(t, native, user).AccessToken
	_ = authtest.SignIn(t, native, target)
	oauth, err := native.CreateGroupOAuthClient(t.Context(), iam.SystemIdentity(), iam.RootGroup(), iam.NewOAuthClient{ClientName: "Remote parity", RedirectURIs: []string{"https://example.test/callback"}, TokenEndpointAuthMethod: iam.OAuthClientSecretBasic, Scope: "openid"})
	require.NoError(t, err)
	jwk := keys.PublicJWK(testKeys().Active.Public(), "remote-parity", "")
	_, err = native.UpsertRemoteApplication(t.Context(), iam.SystemIdentity(), iam.RootGroup(), iam.RemoteApplication{Issuer: "https://remote-parity.example.test", Enabled: true, PublicKeys: []iam.RemoteApplicationKey{{JWK: &jwk}}, RoleMap: map[string]iam.Role{"reader": readRole}})
	require.NoError(t, err)
	server := httptest.NewServer(native.Handler())
	t.Cleanup(server.Close)
	transport, err := remote.New(remote.Config{BaseURL: server.URL + "/api/v1", HTTPClient: server.Client(), Headers: http.Header{"Authorization": []string{"Bearer " + token}}})
	require.NoError(t, err)

	beforeEntitlements := entitlementCalls.Load()
	q := iam.UserQuery{Page: iam.PageRequest{Limit: 1}, Total: true}
	for {
		want, err := native.ListUsers(t.Context(), q)
		require.NoError(t, err)
		got, err := transport.ListUsers(t.Context(), q)
		require.NoError(t, err)
		assertWireEqual(t, want, got)
		if got.Next == "" {
			break
		}
		q.Page.Cursor = got.Next
	}
	require.Equal(t, beforeEntitlements, entitlementCalls.Load(), "WithEntitlements=false must not call the provider through either transport")
	t.Run("entitlements", func(t *testing.T) {
		q := iam.UserQuery{WithEntitlements: true}
		want, err := native.ListUsers(t.Context(), q)
		require.NoError(t, err)
		got, err := transport.ListUsers(t.Context(), q)
		require.NoError(t, err)
		assertWireEqual(t, want, got)
		require.Greater(t, entitlementCalls.Load(), beforeEntitlements)
	})
	t.Run("sessions", func(t *testing.T) {
		want, err := native.Sessions(t.Context(), target.ID)
		require.NoError(t, err)
		got, err := transport.Sessions(t.Context(), target.ID)
		require.NoError(t, err)
		assertWireEqual(t, want, got)
		require.NotEmpty(t, got)
	})
	t.Run("history", func(t *testing.T) {
		q := iam.SessionEventQuery{Kinds: []iam.SessionEventKind{iam.SessionEventCreated}, Page: iam.PageRequest{Limit: 1}}
		want, err := native.ListSessionEvents(t.Context(), target.ID, q)
		require.NoError(t, err)
		got, err := transport.ListSessionEvents(t.Context(), target.ID, q)
		require.NoError(t, err)
		assertWireEqual(t, want, got)
		require.NotEmpty(t, got.Items)
	})
	t.Run("oauth_clients", func(t *testing.T) {
		want, err := native.GroupOAuthClients(t.Context(), iam.RootGroup())
		require.NoError(t, err)
		got, err := transport.GroupOAuthClients(t.Context(), iam.RootGroup())
		require.NoError(t, err)
		assertWireEqual(t, want, got)
		require.Len(t, got, 1)
	})
	t.Run("oauth_client", func(t *testing.T) {
		want, err := native.GroupOAuthClient(t.Context(), iam.RootGroup(), oauth.ClientID)
		require.NoError(t, err)
		got, err := transport.GroupOAuthClient(t.Context(), iam.RootGroup(), oauth.ClientID)
		require.NoError(t, err)
		assertWireEqual(t, want, got)
	})
	t.Run("members", func(t *testing.T) {
		q := iam.MemberQuery{WithUsers: true, LiveOnly: true, Roles: []iam.Role{readRole}, Page: iam.PageRequest{Limit: 1}}
		want, err := native.ListGroupMembers(t.Context(), iam.RootGroup(), q)
		require.NoError(t, err)
		got, err := transport.ListGroupMembers(t.Context(), iam.RootGroup(), q)
		require.NoError(t, err)
		assertWireEqual(t, want, got)
		require.NotEmpty(t, got.Items)
	})
	t.Run("roles", func(t *testing.T) {
		want, err := native.ListGroupRoles(t.Context(), iam.RootGroup())
		require.NoError(t, err)
		got, err := transport.ListGroupRoles(t.Context(), iam.RootGroup())
		require.NoError(t, err)
		assertWireEqual(t, want, got)
		require.NotEmpty(t, got)
	})
	t.Run("role", func(t *testing.T) {
		want, err := native.GroupRole(t.Context(), iam.RootGroup(), readRole)
		require.NoError(t, err)
		got, err := transport.GroupRole(t.Context(), iam.RootGroup(), readRole)
		require.NoError(t, err)
		assertWireEqual(t, want, got)
	})
	t.Run("keys", func(t *testing.T) {
		want, err := native.ListAPIKeys(t.Context(), iam.RootGroup(), iam.PageRequest{})
		require.NoError(t, err)
		got, err := transport.ListAPIKeys(t.Context(), iam.RootGroup(), iam.PageRequest{})
		require.NoError(t, err)
		assertWireEqual(t, want, got)
	})
	t.Run("invitations", func(t *testing.T) {
		want, err := native.ListInvitations(t.Context(), iam.RootGroup(), iam.PageRequest{})
		require.NoError(t, err)
		got, err := transport.ListInvitations(t.Context(), iam.RootGroup(), iam.PageRequest{})
		require.NoError(t, err)
		assertWireEqual(t, want, got)
	})
	t.Run("applications", func(t *testing.T) {
		want, err := native.ListRemoteApplications(t.Context(), iam.RootGroup(), iam.PageRequest{})
		require.NoError(t, err)
		got, err := transport.ListRemoteApplications(t.Context(), iam.RootGroup(), iam.PageRequest{})
		require.NoError(t, err)
		require.Len(t, got.Items, 1)
		require.NotNil(t, got.Items[0].PublicKeys[0].JWK)
		require.NotEmpty(t, got.Items[0].RoleMap)
		assertWireEqual(t, want, got)
	})
	t.Run("provisioning", func(t *testing.T) {
		want, err := native.ProvisioningTargets(t.Context())
		require.NoError(t, err)
		got, err := transport.ProvisioningTargets(t.Context())
		require.NoError(t, err)
		assertWireEqual(t, want, got)
	})
	t.Run("username", func(t *testing.T) {
		name, err := transport.GenerateUsername(t.Context())
		require.NoError(t, err)
		require.NotEmpty(t, name)
		require.NoError(t, native.CheckUsername(t.Context(), name))
	})
	// An authenticated root reader cannot switch account ownership by path alone.
	foreign := iam.NewTenantID()
	require.NoError(t, native.CreateTenant(t.Context(), iam.Tenant{ID: foreign}))
	foreignClient, err := native.ForTenant(t.Context(), foreign)
	require.NoError(t, err)
	foreignUser := authtest.NewUser(t, foreignClient)
	_, nativeErr := native.Sessions(t.Context(), foreignUser.ID)
	require.Error(t, nativeErr)
	_, remoteErr := transport.Sessions(t.Context(), foreignUser.ID)
	require.Error(t, remoteErr)
	nativeCode, ok := iam.AsError(nativeErr)
	require.True(t, ok)
	requireEventErrorCode(t, remoteErr, nativeCode.Code())
	// The server, not retained client configuration, decides whether access remains.
	require.NoError(t, native.RemoveGroupMember(t.Context(), iam.SystemIdentity(), iam.RootGroup(), iam.UserSubject(user.ID)))
	_, err = transport.ListUsers(t.Context(), iam.UserQuery{})
	requireEventErrorCode(t, err, "forbidden")
}
