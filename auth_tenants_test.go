package authkit_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/stretchr/testify/require"
)

func TestTenantAccountsKeepIdentifiersAndViewsSeparate(t *testing.T) {
	root, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.DefaultTenantID = iam.TenantID{} }))
	aID, bID := iam.NewTenantID(), iam.NewTenantID()
	for _, id := range []iam.TenantID{aID, bID} {
		require.NoError(t, root.CreateTenant(t.Context(), iam.Tenant{ID: id}))
		require.NoError(t, root.CreateTenant(t.Context(), iam.Tenant{ID: id}))
		group, err := root.Group(t.Context(), iam.GroupByID(id.String()))
		require.NoError(t, err)
		require.Equal(t, iam.TenantPersona(), group.Persona)
		require.Equal(t, id, group.TenantID)
	}
	a, err := root.ForTenant(t.Context(), aID)
	require.NoError(t, err)
	b, err := root.ForTenant(t.Context(), bID)
	require.NoError(t, err)
	_, err = root.ForTenant(t.Context(), iam.NewTenantID())
	require.ErrorIs(t, err, iam.ErrTenantNotFound)
	ua, err := a.CreateUser(t.Context(), iam.NewUser{Username: "sameuser", Email: "same@example.test", Password: authtest.Password, EmailVerified: true})
	require.NoError(t, err)
	ub, err := b.CreateUser(t.Context(), iam.NewUser{Username: "sameuser", Email: "same@example.test", Password: authtest.Password, EmailVerified: true})
	require.NoError(t, err)
	require.NotEqual(t, ua.ID, ub.ID)
	require.Equal(t, aID, ua.TenantID)
	require.Equal(t, bID, ub.TenantID)
	for _, ref := range []iam.UserRef{iam.UserByEmail("same@example.test"), iam.UserByUsername("sameuser")} {
		found, err := a.User(t.Context(), ref)
		require.NoError(t, err)
		require.Equal(t, ua.ID, found.ID)
		found, err = b.User(t.Context(), ref)
		require.NoError(t, err)
		require.Equal(t, ub.ID, found.ID)
	}
	_, err = a.User(t.Context(), iam.UserByID(ub.ID))
	require.ErrorIs(t, err, iam.ErrUserNotFound)
	info, err := a.UserInfo().Get(t.Context(), []string{ua.ID, ub.ID})
	require.NoError(t, err)
	require.Contains(t, info, ua.ID)
	require.NotContains(t, info, ub.ID)
	page, err := a.ListUsers(t.Context(), iam.UserQuery{Status: iam.UserStatusAny, Total: true})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	require.EqualValues(t, 1, *page.Total)
	for _, entry := range []struct {
		client *authkit.Client
		other  *authkit.Client
		user   iam.User
		tenant iam.TenantID
	}{{a, b, ua, aID}, {b, a, ub, bID}} {
		tokens := authtest.SignIn(t, entry.client, authtest.User{User: entry.user, Email: "same@example.test", Password: authtest.Password})
		claims, err := root.Verify(t.Context(), tokens.AccessToken)
		require.NoError(t, err)
		identity, ok := claims.Identity()
		require.True(t, ok)
		require.Equal(t, entry.user.ID, identity.Subject)
		require.Equal(t, entry.tenant.String(), identity.TenantID)
		// A wrong tenant cannot consume, rotate, or revoke the other tenant's
		// refresh credential. Its owner can still redeem it immediately after.
		body := map[string]any{"grant_type": "refresh_token", "refresh_token": tokens.RefreshToken}
		wrong := tenantPOST(t, entry.other, "/token", body)
		require.Equal(t, http.StatusUnauthorized, wrong.Code)
		correct := tenantPOST(t, entry.client, "/token", body)
		require.Equal(t, http.StatusOK, correct.Code)
		var refreshed httpapi.AuthResult
		require.NoError(t, json.Unmarshal(correct.Body.Bytes(), &refreshed))
		require.NotNil(t, refreshed.TokenSet)
		claims, err = root.Verify(t.Context(), refreshed.TokenSet.AccessToken)
		require.NoError(t, err)
		identity, ok = claims.Identity()
		require.True(t, ok)
		require.Equal(t, entry.tenant.String(), identity.TenantID)
		request := httptest.NewRequest(http.MethodGet, "/protected", nil)
		request.Header.Set("Authorization", "Bearer "+refreshed.TokenSet.AccessToken)
		verified, err := root.Authenticator().Authenticate(request)
		require.NoError(t, err)
		actor, err := entry.other.ResolveTenantActor(t.Context(), verified)
		require.NoError(t, err)
		require.Equal(t, iam.TenantActor{AccountID: entry.user.ID, TenantID: entry.tenant}, actor)
	}
	require.NoError(t, a.Close(t.Context())) // A borrowing view never closes the root.
	_, err = b.User(t.Context(), iam.UserByID(ub.ID))
	require.NoError(t, err)
}

func tenantPOST(t *testing.T, client *authkit.Client, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, client.APIBase()+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	return rec
}

func TestTenantPasswordlessAndRecoveryProofsStaySeparate(t *testing.T) {
	root, outbox := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.DefaultTenantID = iam.TenantID{}
		c.Registration.PasswordlessLogin = true
	}))
	views := make([]*authkit.Client, 2)
	users := make([]iam.User, 2)
	for i := range views {
		id := iam.NewTenantID()
		require.NoError(t, root.CreateTenant(t.Context(), iam.Tenant{ID: id}))
		var err error
		views[i], err = root.ForTenant(t.Context(), id)
		require.NoError(t, err)
		users[i], err = views[i].CreateUser(t.Context(), iam.NewUser{Username: "sameuser", Email: "same@example.test", EmailVerified: true, Password: authtest.Password})
		require.NoError(t, err)
	}
	links := make([]string, 2)
	for i, view := range views {
		res := tenantPOST(t, view, "/passwordless/start", map[string]string{"identifier": "same@example.test", "mode": "link"})
		require.Equal(t, http.StatusAccepted, res.Code)
		links[i] = outbox.Last(t, iam.MessageVerification, "same@example.test").Token
		require.NotEmpty(t, links[i])
	}
	for i, view := range views {
		wrong := tenantPOST(t, views[1-i], "/passwordless/confirm", map[string]string{"token": links[i]})
		require.GreaterOrEqual(t, wrong.Code, 400)
		require.Less(t, wrong.Code, 500)
		correct := tenantPOST(t, view, "/passwordless/confirm", map[string]string{"token": links[i]})
		require.Equal(t, http.StatusOK, correct.Code)
		var result httpapi.AuthResult
		require.NoError(t, json.Unmarshal(correct.Body.Bytes(), &result))
		require.Equal(t, users[i].ID, result.User.ID)
	}
	reset := tenantPOST(t, views[0], "/password/reset/request", map[string]string{"identifier": "same@example.test"})
	require.Equal(t, http.StatusAccepted, reset.Code)
	resetToken := outbox.Last(t, iam.MessagePasswordReset, "same@example.test").Token
	require.NotEmpty(t, resetToken)
	const newPassword = "Changed-tenant-password-9"
	resetBody := map[string]string{"token": resetToken, "new_password": newPassword}
	wrong := tenantPOST(t, views[1], "/password/reset/confirm", resetBody)
	require.GreaterOrEqual(t, wrong.Code, 400)
	require.Less(t, wrong.Code, 500)
	correct := tenantPOST(t, views[0], "/password/reset/confirm", resetBody)
	require.Equal(t, http.StatusNoContent, correct.Code)
	for i, password := range []string{newPassword, authtest.Password} {
		tokens := authtest.SignIn(t, views[i], authtest.User{User: users[i], Email: "same@example.test", Password: password})
		claims, err := root.Verify(t.Context(), tokens.AccessToken)
		require.NoError(t, err)
		require.Equal(t, users[i].ID, claims.UserID)
	}
}
