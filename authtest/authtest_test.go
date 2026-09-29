package authtest_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/devicekey"
	"github.com/open-rails/authkit/iam"
)

// The helpers a host's test starts from: users, roles, sessions and an
// authenticator app, against a real Client.
func TestHostSetup(t *testing.T) {
	ctx := t.Context()
	rbac := authkit.NewRoles()
	channel := rbac.Persona("channel")
	edit := channel.Permission("posts", "edit")
	purge := channel.Permission("posts", "purge")
	channel.RequireMFA(purge)
	moderator := channel.Role("moderator", edit)
	admin := channel.Role("admin", edit, purge)
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.Roles = rbac }))
	g, err := auth.CreateGroup(ctx, iam.NewGroup{Persona: channel.Persona})
	require.NoError(t, err)
	group := iam.GroupByID(g.ID)

	alice := authtest.NewUser(t, auth)
	require.True(t, alice.EmailVerified)
	authtest.GrantRole(t, auth, group, iam.UserSubject(alice.ID), moderator)
	can, err := auth.Can(ctx, iam.UserActor(alice.ID), group, edit)
	require.NoError(t, err)
	require.True(t, can)
	tokens := authtest.SignIn(t, auth, alice)
	require.NotEmpty(t, tokens.RefreshToken)
	claims, err := auth.Verifier().Verify(ctx, tokens.AccessToken)
	require.NoError(t, err)
	require.Equal(t, alice.ID, claims.UserID)
	require.NotContains(t, claims.AMR, "mfa")

	// A role reaching an MFA permission needs the second factor first; the
	// session then carries it.
	bob := authtest.NewUser(t, auth)
	bob.TOTP = authtest.EnrollTOTP(t, auth, bob)
	authtest.GrantRole(t, auth, group, iam.UserSubject(bob.ID), admin)
	claims, err = auth.Verifier().Verify(ctx, authtest.SignIn(t, auth, bob).AccessToken)
	require.NoError(t, err)
	require.Contains(t, claims.AMR, "mfa")
}

// A sign-up completed with the code the Outbox captured.
func TestOutboxCompletesSignUp(t *testing.T) {
	auth, outbox := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Registration.Verification = iam.RegistrationVerificationRequired
	}))
	api := httptest.NewServer(auth.Handler())
	t.Cleanup(api.Close)
	post := func(path, body string) int {
		resp, err := http.Post(api.URL+"/api/v1"+path, "application/json", strings.NewReader(body))
		require.NoError(t, err)
		resp.Body.Close()
		return resp.StatusCode
	}
	const email = "carol@example.com"
	require.Equal(t, http.StatusAccepted, post("/register", `{"identifier":"`+email+`","username":"carol","password":"`+authtest.Password+`"}`))
	sent := outbox.Last(t, authtest.Verification, email)
	require.Equal(t, "email", sent.Channel)
	require.Equal(t, "signup", sent.Purpose)
	require.NotEmpty(t, sent.Code)
	require.NotEmpty(t, sent.Token)
	require.Equal(t, http.StatusOK, post("/verify/confirm", `{"identifier":"`+email+`","code":"`+sent.Code+`"}`))

	tokens := authtest.SignIn(t, auth, authtest.User{User: iam.User{Email: email}, Password: authtest.Password})
	require.NotEmpty(t, tokens.AccessToken)
	require.Empty(t, outbox.Messages(authtest.LoginCode, email))
}

// A device key enrolled with the emailed code signs in on its own.
func TestEnrollDeviceKey(t *testing.T) {
	auth, outbox := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.DeviceKeys.Enabled = true }))
	u := authtest.NewUser(t, auth)
	key := authtest.EnrollDeviceKey(t, auth, outbox, u)
	require.NotEmpty(t, key.ID)
	require.Len(t, outbox.Messages(authtest.DeviceKeyEnrolled, u.Email), 1, "the existing owner hears of the new key")

	api := httptest.NewServer(auth.Handler())
	t.Cleanup(api.Close)
	c, err := devicekey.NewClient(api.URL+"/api/v1", nil)
	require.NoError(t, err)
	session, err := c.Login(t.Context(), key.ID, key.Key)
	require.NoError(t, err)
	claims, err := auth.Verifier().Verify(t.Context(), session.AccessToken)
	require.NoError(t, err)
	require.Equal(t, u.ID, claims.UserID)
}

// A replica serves the same accounts; a stale session must step up before a
// sensitive change.
func TestReplicaAndStaleSession(t *testing.T) {
	auth, _ := authtest.New(t)
	alice := authtest.NewUser(t, auth)
	replica := authtest.Replica(t, auth)
	tokens := authtest.SignIn(t, replica, alice)
	sessions, err := auth.Sessions(t.Context(), alice.ID)
	require.NoError(t, err)
	require.Len(t, sessions, 1, "a session the replica issued is the deployment's")

	api := httptest.NewServer(auth.Handler())
	t.Cleanup(api.Close)
	startTOTP := func() (int, string) {
		req, err := http.NewRequest(http.MethodPost, api.URL+"/api/v1/user/2fa", strings.NewReader(`{"method":"totp"}`))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, string(body)
	}
	status, body := startTOTP()
	require.Equal(t, http.StatusOK, status, body)
	authtest.StaleSession(t, auth, tokens.AccessToken)
	status, body = startTOTP()
	require.Equal(t, http.StatusForbidden, status, body)
	require.Contains(t, body, "step_up_required")
}
