package authkit_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

func TestTenantGlobalAccountInviterDoesNotGainMembershipPowers(t *testing.T) {
	roles := authkit.NewRoles(authkit.APIKeys)
	inviteRole := roles.Root.Role("account-inviter", roles.Root.Users.Invite)
	tenantReader := roles.Tenant.Role("reader", roles.Tenant.Users.Read)
	app := roles.Persona("app", authkit.APIKeys)
	read := app.Permission("content", "read")
	appReader := app.Role("reader", read)
	shared, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.DefaultTenantID = iam.TenantID{}
		c.Roles = roles
		c.TwoFactor.Mode = iam.TwoFactorDisabled
		c.Registration.NativeUserMode = iam.RegistrationModeInviteOnly
	}))
	aID, bID := iam.NewTenantID(), iam.NewTenantID()
	for _, id := range []iam.TenantID{aID, bID} {
		require.NoError(t, shared.CreateTenant(t.Context(), iam.Tenant{ID: id}))
	}
	a, err := shared.ForTenant(t.Context(), aID)
	require.NoError(t, err)
	b, err := shared.ForTenant(t.Context(), bID)
	require.NoError(t, err)
	actor := authtest.NewUser(t, a)
	authtest.GrantRole(t, a, iam.RootGroup(), iam.UserSubject(actor.ID), inviteRole)
	target := iam.GroupByID(bID.String())
	native, err := b.CreateInvitation(t.Context(), iam.UserIdentity(actor.ID), target, iam.NewInvitation{Email: "native@example.test"})
	require.NoError(t, err)
	require.True(t, native.Invitation.Role.IsZero())
	require.Equal(t, bID, native.Invitation.TenantID)
	_, err = b.CreateInvitation(t.Context(), iam.UserIdentity(actor.ID), target, iam.NewInvitation{Email: "role@example.test", Role: tenantReader})
	require.Error(t, err, "account invitation authority must not grant a membership role")
	group, err := a.CreateGroup(t.Context(), iam.NewGroup{Persona: app.Persona})
	require.NoError(t, err)
	pinned := iam.PinnedTo(iam.Within(iam.UserIdentity(actor.ID), roles.Root.Users.Invite), group.ID)
	_, err = b.CreateInvitation(t.Context(), pinned, target, iam.NewInvitation{Email: "pinned@example.test"})
	require.Error(t, err, "a root permission ceiling cannot widen an app pin")
	rootKey, err := a.CreateAPIKey(t.Context(), iam.SystemIdentity(), iam.RootGroup(), iam.NewAPIKey{Name: "root-invite", Role: inviteRole})
	require.NoError(t, err)
	appKey, err := a.CreateAPIKey(t.Context(), iam.SystemIdentity(), iam.GroupByID(group.ID), iam.NewAPIKey{Name: "app-read", Role: appReader})
	require.NoError(t, err)
	allowed, err := shared.Can(t.Context(), iam.APIKeyIdentity(rootKey.APIKey.ID), iam.RootGroup(), roles.Root.Users.Invite)
	require.NoError(t, err)
	require.True(t, allowed)
	for _, key := range []iam.APIKeyCreated{rootKey, appKey} {
		_, err = b.CreateInvitation(t.Context(), iam.APIKeyIdentity(key.APIKey.ID), target, iam.NewInvitation{Email: "key@example.test"})
		require.ErrorIs(t, err, iam.ErrInsufficientAuthority, "keys remain forbidden as invitation issuers")
	}
	allowed, err = shared.Can(t.Context(), iam.Within(iam.APIKeyIdentity(appKey.APIKey.ID), roles.Root.Users.Invite), iam.RootGroup(), roles.Root.Users.Invite)
	require.NoError(t, err)
	require.False(t, allowed)
	allowed, err = shared.Can(t.Context(), iam.Within(iam.APIKeyIdentity(rootKey.APIKey.ID), read), iam.RootGroup(), roles.Root.Users.Invite)
	require.NoError(t, err)
	require.False(t, allowed)
	request := func(token string, role string) *httptest.ResponseRecorder {
		body := map[string]string{"email": "http@example.test"}
		if role != "" {
			body["role"] = role
		}
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, b.APIBase()+"/groups/"+bID.String()+"/invitations", strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		b.Handler().ServeHTTP(w, req)
		return w
	}
	token := authtest.SignIn(t, a, actor).AccessToken
	require.Equal(t, http.StatusAccepted, request(token, "").Code)
	require.Equal(t, http.StatusForbidden, request(token, tenantReader.String()).Code)
	for _, key := range []iam.APIKeyCreated{rootKey, appKey} {
		require.Equal(t, http.StatusForbidden, request(key.Secret, "").Code)
	}
	require.NoError(t, a.RemoveGroupMember(t.Context(), iam.SystemIdentity(), iam.RootGroup(), iam.UserSubject(actor.ID)))
	invitations, err := b.ListInvitations(t.Context(), target, iam.PageRequest{})
	require.NoError(t, err)
	found := false
	for _, invitation := range invitations.Items {
		if invitation.ID == native.Invitation.ID {
			found = true
			require.NotNil(t, invitation.RevokedAt, "the global inviter's credential must die with its authority")
		}
	}
	require.True(t, found)
}
