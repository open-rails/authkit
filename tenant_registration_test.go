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

func TestTenantAnonymousRegistrationProofsRespectDirectory(t *testing.T) {
	shared, outbox := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.DefaultTenantID = iam.TenantID{}
		c.Registration.Verification = iam.RegistrationVerificationRequired
	}))
	views := make([]*authkit.Client, 2)
	for i := range views {
		id := iam.NewTenantID()
		require.NoError(t, shared.CreateTenant(t.Context(), iam.Tenant{ID: id}))
		var err error
		views[i], err = shared.ForTenant(t.Context(), id)
		require.NoError(t, err)
	}
	user := authtest.NewUser(t, views[0])
	foreign := authtest.SignIn(t, views[0], user).AccessToken
	for _, mode := range []string{"code", "link"} {
		t.Run(mode, func(t *testing.T) {
			email := mode + "@example.test"
			reg := tenantPOST(t, views[1], "/register", map[string]string{"identifier": email, "username": "registered" + mode, "password": authtest.Password})
			require.Equal(t, http.StatusAccepted, reg.Code)
			sent := outbox.Last(t, iam.MessageVerification, email)
			proof := map[string]string{"identifier": email, "code": sent.Code}
			target := views[1]
			if mode == "link" {
				proof = map[string]string{"token": sent.Token}
				target = shared
			}
			raw, err := json.Marshal(proof)
			require.NoError(t, err)
			request := httptest.NewRequest(http.MethodPost, views[1].APIBase()+"/verify/confirm", bytes.NewReader(raw))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer "+foreign)
			blocked := httptest.NewRecorder()
			views[1].Handler().ServeHTTP(blocked, request)
			require.Equal(t, http.StatusForbidden, blocked.Code, "a signed-in foreign account cannot become a target member")
			wrong := tenantPOST(t, views[0], "/verify/confirm", proof)
			require.GreaterOrEqual(t, wrong.Code, 400)
			require.Less(t, wrong.Code, 500)
			correct := tenantPOST(t, target, "/verify/confirm", proof)
			require.Equal(t, http.StatusOK, correct.Code)
			var result httpapi.AuthResult
			require.NoError(t, json.Unmarshal(correct.Body.Bytes(), &result))
			require.NotNil(t, result.User)
			require.Equal(t, email, *result.User.Email)
			own, err := views[1].User(t.Context(), iam.UserByEmail(email))
			require.NoError(t, err)
			require.Equal(t, own.ID, result.User.ID)
			_, err = views[0].User(t.Context(), iam.UserByEmail(email))
			require.ErrorIs(t, err, iam.ErrUserNotFound)
		})
	}
}
