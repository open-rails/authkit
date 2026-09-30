package authtest_test

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/devicekey"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testkeys"
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
	claims, err := auth.Verify(ctx, tokens.AccessToken)
	require.NoError(t, err)
	require.Equal(t, alice.ID, claims.UserID)
	require.NotContains(t, claims.AMR, "mfa")

	// A role reaching an MFA permission needs the second factor first; the
	// session then carries it.
	bob := authtest.NewUser(t, auth)
	bob.TOTP = authtest.EnrollTOTP(t, auth, bob)
	authtest.GrantRole(t, auth, group, iam.UserSubject(bob.ID), admin)
	claims, err = auth.Verify(ctx, authtest.SignIn(t, auth, bob).AccessToken)
	require.NoError(t, err)
	require.Contains(t, claims.AMR, "mfa")

	authtest.RevokeRole(t, auth, group, iam.UserSubject(alice.ID), moderator)
	can, err = auth.Can(ctx, iam.UserActor(alice.ID), group, edit)
	require.NoError(t, err)
	require.False(t, can)
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
	sent := outbox.Last(t, iam.MessageVerification, email)
	require.Equal(t, "email", sent.Channel)
	require.Equal(t, iam.PurposeSignup, sent.Purpose)
	require.NotEmpty(t, sent.Code)
	require.NotEmpty(t, sent.Token)
	require.Equal(t, http.StatusOK, post("/verify/confirm", `{"identifier":"`+email+`","code":"`+sent.Code+`"}`))

	tokens := authtest.SignIn(t, auth, authtest.User{Email: email, Password: authtest.Password})
	require.NotEmpty(t, tokens.AccessToken)
	require.Empty(t, outbox.Messages(iam.MessageLoginCode, email))
}

// A device key enrolled with the emailed code signs in on its own.
func TestEnrollDeviceKey(t *testing.T) {
	auth, outbox := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.DeviceKeys.Enabled = true }))
	u := authtest.NewUser(t, auth)
	key := authtest.EnrollDeviceKey(t, auth, outbox, u)
	require.NotEmpty(t, key.ID)
	require.Len(t, outbox.Messages(iam.MessageDeviceKeyEnrolled, u.Email), 1, "the existing owner hears of the new key")

	api := httptest.NewServer(auth.Handler())
	t.Cleanup(api.Close)
	c, err := devicekey.NewClient(api.URL+"/api/v1", nil)
	require.NoError(t, err)
	session, err := c.Login(t.Context(), key.ID, key.Key)
	require.NoError(t, err)
	claims, err := auth.Verify(t.Context(), session.AccessToken)
	require.NoError(t, err)
	require.Equal(t, u.ID, claims.UserID)
}

// A replica serves the same accounts; a stale session must step up before a
// sensitive change.
func TestReplicaAndStaleSession(t *testing.T) {
	auth, _ := authtest.New(t)
	testReplicaAndStaleSession(t, auth)
}

// Replica and StaleSession take a Client the host built itself, not only one
// from New.
func TestReplicaAndStaleSessionOfAHostClient(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	totpKey := make([]byte, 32)
	_, _ = rand.Read(totpKey)
	auth, err := authkit.New(t.Context(), authkit.Config{
		Token:     authkit.TokenConfig{Issuer: "https://host.example", IssuedAudiences: []string{"host"}},
		TwoFactor: authkit.TwoFactorConfig{TOTPSecretKey: totpKey}, // the root owner's MFA must be enrollable
		HTTP:      &authkit.HTTPConfig{DirectPeerIP: true},
	}, authkit.Deps{Postgres: pg.Pool, KeySource: testkeys.Source(testkeys.RSA("host-built"))})
	require.NoError(t, err)
	t.Cleanup(auth.Close)
	testReplicaAndStaleSession(t, auth)
}

func testReplicaAndStaleSession(t *testing.T, auth *authkit.Client) {
	ctx := t.Context()
	alice := authtest.NewUser(t, auth)
	replica := authtest.Replica(t, auth)
	tokens := authtest.SignIn(t, replica, alice)
	sessions, err := auth.Sessions(ctx, alice.ID)
	require.NoError(t, err)
	require.Len(t, sessions, 1, "a session the replica issued is the deployment's")

	claims, err := auth.Verify(ctx, tokens.AccessToken)
	require.NoError(t, err)
	require.NoError(t, auth.CheckRecentSignIn(ctx, claims))
	stale := authtest.StaleSession(t, auth, tokens.AccessToken)
	claims, err = auth.Verify(ctx, stale)
	require.NoError(t, err)
	requireCode(t, auth.CheckRecentSignIn(ctx, claims), "step_up_required")
}

// A deployment that requires a second factor: SignIn enrolls an
// authenticator app with the enrollment token, then answers the second factor
// with it on every later sign-in.
func TestSignInFinishesARequiredEnrollment(t *testing.T) {
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.TwoFactor.Mode = iam.TwoFactorRequired }))
	u := authtest.NewUser(t, auth)
	require.Nil(t, authtest.TOTPOf(u.ID))
	for range 2 {
		claims, err := auth.Verify(t.Context(), authtest.SignIn(t, auth, u).AccessToken)
		require.NoError(t, err)
		require.Contains(t, claims.AMR, "mfa")
		require.NotNil(t, authtest.TOTPOf(u.ID), "SignIn remembers the app it enrolled")
	}
}

func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	e, ok := iam.AsError(err)
	require.True(t, ok, "not an AuthKit error: %v", err)
	require.Equal(t, code, e.Code())
}
