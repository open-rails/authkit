package apitest_test

import (
	"net/http"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/stretchr/testify/require"
)

func TestMFAProtectedRoleCanBeGrantedBeforeEnrollment(t *testing.T) {
	roles := authkit.NewRoles()
	manage := roles.Root.Users.Manage
	roles.Root.RequireMFA(manage)
	admin := roles.Root.Role("admin", manage)
	client, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Roles = roles
		c.TwoFactor.Mode = iam.TwoFactorOptional
	}))
	user := authtest.NewUser(t, client)
	session := authtest.SignIn(t, client, user)
	_, err := client.SetGroupRole(t.Context(), iam.SystemIdentity(), iam.RootGroup(), iam.UserSubject(user.ID), admin)
	require.NoError(t, err, "promotion should succeed before the user enrolls MFA")
	require.Equal(t, admin, roleOfIn(t, client, iam.RootGroup(), iam.UserSubject(user.ID)))
	_, err = client.Verify(t.Context(), session.AccessToken)
	require.ErrorIs(t, err, iam.ErrTwoFAEnrollmentRequired, "the existing bearer must not acquire protected access")
	can, err := client.Can(t.Context(), iam.UserIdentity(user.ID), iam.RootGroup(), manage)
	require.ErrorIs(t, err, iam.ErrTwoFAEnrollmentRequired)
	require.False(t, can)
	api := newAPI(t, client)
	refresh := api.do(request{method: http.MethodPost, path: "/token", body: map[string]string{"grant_type": "refresh_token", "refresh_token": *session.RefreshToken}})
	var resumed httpapi.AuthResult
	refresh.decode(t, &resumed)
	require.Equal(t, httpapi.AuthEnrollmentRequired, resumed.Status, refresh.String())
	require.NotNil(t, resumed.Enrollment)
	// An explicit false cannot waive a requirement derived from a held role.
	optional := false
	_, err = client.UpdateUser(t.Context(), iam.SystemIdentity(), user.ID, iam.UserUpdate{MFARequired: &optional})
	require.NoError(t, err)
	_, err = client.Verify(t.Context(), session.AccessToken)
	require.ErrorIs(t, err, iam.ErrTwoFAEnrollmentRequired)
	first := api.do(request{method: http.MethodPost, path: "/password/login", body: map[string]string{"identifier": user.Email, "password": user.Password}})
	var pending httpapi.AuthResult
	first.decode(t, &pending)
	require.Equal(t, httpapi.AuthEnrollmentRequired, pending.Status, first.String())
	require.NotNil(t, pending.Enrollment)
	require.Nil(t, pending.TokenSet)
	complete := authtest.SignIn(t, client, user)
	_, err = client.Verify(t.Context(), complete.AccessToken)
	require.NoError(t, err)
	can, err = client.Can(t.Context(), iam.UserIdentity(user.ID), iam.RootGroup(), manage)
	require.NoError(t, err)
	require.True(t, can)
	removed := api.do(request{method: http.MethodDelete, path: "/me/2fa", token: complete.AccessToken})
	require.Equal(t, http.StatusForbidden, removed.status, removed.String())
	require.Equal(t, "2fa_required_by_policy", removed.code())
	require.Equal(t, admin, roleOfIn(t, client, iam.RootGroup(), iam.UserSubject(user.ID)), "a required factor cannot be removed by silently demoting the account")
}

func TestIndividualMFARequirementAppliesToExistingSessions(t *testing.T) {
	client, _ := authtest.New(t)
	user := authtest.NewUser(t, client)
	session := authtest.SignIn(t, client, user)
	stale := authtest.StaleSession(t, client, session.AccessToken)
	required := true
	updated, err := client.UpdateUser(t.Context(), iam.SystemIdentity(), user.ID, iam.UserUpdate{MFARequired: &required})
	require.NoError(t, err)
	require.True(t, updated.MFARequired)
	optional := false
	_, err = client.UpdateUser(t.Context(), iam.UserIdentity(user.ID), user.ID, iam.UserUpdate{MFARequired: &optional})
	require.Error(t, err, "self-service cannot remove an administrator's requirement")
	stillRequired, err := client.User(t.Context(), iam.UserByID(user.ID))
	require.NoError(t, err)
	require.True(t, stillRequired.MFARequired)
	_, err = client.Verify(t.Context(), stale)
	require.ErrorIs(t, err, iam.ErrTwoFAEnrollmentRequired)
	api := newAPI(t, client)
	refresh := api.do(request{method: http.MethodPost, path: "/token", body: map[string]string{"grant_type": "refresh_token", "refresh_token": *session.RefreshToken}})
	var pending httpapi.AuthResult
	refresh.decode(t, &pending)
	require.Equal(t, httpapi.AuthReauthenticationRequired, pending.Status, refresh.String())
	require.Equal(t, user.ID, pending.Reauthentication.UserID)
	require.Nil(t, pending.TokenSet)
	// Clearing an explicit requirement restores the still-valid session.
	required = false
	_, err = client.UpdateUser(t.Context(), iam.SystemIdentity(), user.ID, iam.UserUpdate{MFARequired: &required})
	require.NoError(t, err)
	_, err = client.Verify(t.Context(), stale)
	require.NoError(t, err)
}

func TestMFAUpgradeChallengesAnExistingFactorWithoutReenrollment(t *testing.T) {
	client, _ := authtest.New(t)
	user := authtest.NewUser(t, client)
	old := authtest.SignIn(t, client, user)
	authtest.EnrollTOTP(t, client, user)
	required := true
	_, err := client.UpdateUser(t.Context(), iam.SystemIdentity(), user.ID, iam.UserUpdate{MFARequired: &required})
	require.NoError(t, err)
	_, err = client.Verify(t.Context(), old.AccessToken)
	failure, ok := iam.AsError(err)
	require.True(t, ok)
	require.Equal(t, "2fa_required", failure.Code())
	api := newAPI(t, client)
	response := api.do(request{method: http.MethodPost, path: "/token", body: map[string]string{"grant_type": "refresh_token", "refresh_token": *old.RefreshToken}})
	var continuation httpapi.AuthResult
	response.decode(t, &continuation)
	require.Equal(t, httpapi.AuthSecondFactorRequired, continuation.Status, response.String())
	require.NotNil(t, continuation.SecondFactor)
	require.Equal(t, "totp", continuation.SecondFactor.Factor.Method)
	require.Nil(t, continuation.Enrollment)
}
