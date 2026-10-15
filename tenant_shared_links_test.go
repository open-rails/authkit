package authkit_test

import (
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

func TestTenantSharedFrontendRoutesOnlyTheProvenLinkOwner(t *testing.T) {
	shared, outbox := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.DefaultTenantID = iam.TenantID{}
		c.Registration.PasswordlessLogin = true
		c.Frontend.BaseURL = "https://shared.example.test"
	}))
	views := make([]*authkit.Client, 2)
	users := make([]iam.User, 2)
	for i := range views {
		id := iam.NewTenantID()
		require.NoError(t, shared.CreateTenant(t.Context(), iam.Tenant{ID: id}))
		var err error
		views[i], err = shared.ForTenant(t.Context(), id)
		require.NoError(t, err)
		users[i], err = views[i].CreateUser(t.Context(), iam.NewUser{Email: "shared@example.test", Username: "shareduser", Password: authtest.Password, EmailVerified: true})
		require.NoError(t, err)
	}
	request := tenantPOST(t, views[1], "/password/reset/request", map[string]string{"identifier": "shared@example.test"})
	require.Equal(t, http.StatusAccepted, request.Code)
	proof := outbox.Last(t, iam.MessagePasswordReset, "shared@example.test").Token
	newPassword := "Meadow-crystal-chestnut-9"
	reset := map[string]string{"token": proof, "new_password": newPassword}
	wrong := tenantPOST(t, views[0], "/password/reset/confirm", reset)
	require.GreaterOrEqual(t, wrong.Code, 400)
	correct := tenantPOST(t, shared, "/password/reset/confirm", reset)
	require.Equal(t, http.StatusNoContent, correct.Code)
	for i, password := range []string{authtest.Password, newPassword} {
		tokens := authtest.SignIn(t, views[i], authtest.User{User: users[i], Email: "shared@example.test", Password: password})
		claims, err := shared.Verify(t.Context(), tokens.AccessToken)
		require.NoError(t, err)
		require.Equal(t, users[i].ID, claims.UserID)
	}
	request = tenantPOST(t, views[1], "/passwordless/start", map[string]string{"identifier": "shared@example.test", "mode": "link"})
	require.Equal(t, http.StatusAccepted, request.Code)
	proof = outbox.Last(t, iam.MessageVerification, "shared@example.test").Token
	confirm := map[string]string{"token": proof}
	wrong = tenantPOST(t, views[0], "/passwordless/confirm", confirm)
	require.GreaterOrEqual(t, wrong.Code, 400)
	correct = tenantPOST(t, shared, "/passwordless/confirm", confirm)
	require.Equal(t, http.StatusOK, correct.Code)
	var result httpapi.AuthResult
	require.NoError(t, json.Unmarshal(correct.Body.Bytes(), &result))
	require.Equal(t, users[1].ID, result.User.ID)
	// The central personal endpoint follows only a verified signed owner.
	profileRequest := httptest.NewRequest(http.MethodGet, shared.APIBase()+"/me", nil)
	profileRequest.Header.Set("Authorization", "Bearer "+result.TokenSet.AccessToken)
	profile := httptest.NewRecorder()
	shared.Handler().ServeHTTP(profile, profileRequest)
	require.Equal(t, http.StatusOK, profile.Code)

	// A second-factor continuation from the shared link still belongs to B;
	// a wrong explicit mount must not spend its challenge or TOTP code.
	app := authtest.EnrollTOTP(t, views[1], authtest.User{User: users[1], Email: "shared@example.test", Password: newPassword})
	request = tenantPOST(t, views[1], "/passwordless/start", map[string]string{"identifier": "shared@example.test", "mode": "link"})
	require.Equal(t, http.StatusAccepted, request.Code)
	proof = outbox.Last(t, iam.MessageVerification, "shared@example.test").Token
	challengeResponse := tenantPOST(t, shared, "/passwordless/confirm", map[string]string{"token": proof})
	require.Equal(t, http.StatusOK, challengeResponse.Code)
	var challenge httpapi.AuthResult
	require.NoError(t, json.Unmarshal(challengeResponse.Body.Bytes(), &challenge))
	require.NotNil(t, challenge.SecondFactor)
	completion := map[string]string{"user_id": users[1].ID, "challenge": challenge.SecondFactor.Challenge, "factor_id": challenge.SecondFactor.Factor.ID, "code": app.Code(t)}
	wrong = tenantPOST(t, views[0], "/2fa/verify", completion)
	require.GreaterOrEqual(t, wrong.Code, 400)
	require.Less(t, wrong.Code, 500)
	correct = tenantPOST(t, shared, "/2fa/verify", completion)
	require.Equal(t, http.StatusOK, correct.Code)
	require.NoError(t, json.Unmarshal(correct.Body.Bytes(), &result))
	require.Equal(t, users[1].ID, result.User.ID)
}
