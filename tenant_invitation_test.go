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
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/stretchr/testify/require"
)

func TestTenantInvitationsRouteProofsWithoutSharingAccounts(t *testing.T) {
	shared, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.DefaultTenantID = iam.TenantID{}
		c.Registration.NativeUserMode = iam.RegistrationModeInviteOnly
		c.Registration.Verification = iam.RegistrationVerificationNone
		c.TwoFactor.Mode = iam.TwoFactorDisabled
	}))
	views := make([]*authkit.Client, 2)
	for i := range views {
		id := iam.NewTenantID()
		require.NoError(t, shared.CreateTenant(t.Context(), iam.Tenant{ID: id}))
		var err error
		views[i], err = shared.ForTenant(t.Context(), id)
		require.NoError(t, err)
	}
	a, err := views[0].CreateUser(t.Context(), iam.NewUser{Email: "invited@example.test", Username: "inviteperson", Password: authtest.Password, EmailVerified: true})
	require.NoError(t, err)
	// The same identifier may register independently in B. A wrong mount cannot
	// consume B's invitation or use it as permission to register in A.
	// The group follows the explicit tenant carried by the view's user record.
	bSeed, err := views[1].CreateUser(t.Context(), iam.NewUser{Email: "seed@example.test", Username: "seedperson", Password: authtest.Password, EmailVerified: true})
	require.NoError(t, err)
	group := iam.GroupByID(bSeed.TenantID.String())
	invite, err := views[1].CreateInvitation(t.Context(), iam.SystemIdentity(), group, iam.NewInvitation{Email: "invited@example.test"})
	require.NoError(t, err)
	body := map[string]string{"identifier": "invited@example.test", "username": "inviteperson", "password": authtest.Password, "invite_code": invite.Code}
	wrong := tenantPOST(t, views[0], "/register", body)
	require.GreaterOrEqual(t, wrong.Code, 400)
	require.Less(t, wrong.Code, 500)
	good := tenantPOST(t, shared, "/register", body)
	require.Equal(t, http.StatusOK, good.Code)
	var result httpapi.AuthResult
	require.NoError(t, json.Unmarshal(good.Body.Bytes(), &result))
	require.NotEqual(t, a.ID, result.User.ID)
	require.Equal(t, bSeed.TenantID, result.User.TenantID)
	held, err := views[1].GroupRoles(t.Context(), group, []iam.Subject{iam.UserSubject(result.User.ID)})
	require.NoError(t, err)
	require.True(t, held[iam.UserSubject(result.User.ID)].IsZero(), "registration-only invite creates no group membership")
	replay := tenantPOST(t, shared, "/register", map[string]string{"identifier": "another@example.test", "username": "anotherperson", "password": authtest.Password, "invite_code": invite.Code})
	require.GreaterOrEqual(t, replay.Code, 400)
	// An existing account accepts a registration-only invite without assigning
	// a role. The foreign account with the same email still cannot accept it.
	second, err := views[1].CreateInvitation(t.Context(), iam.SystemIdentity(), group, iam.NewInvitation{Email: "invited@example.test"})
	require.NoError(t, err)
	aToken := authtest.SignIn(t, views[0], authtest.User{User: a, Email: "invited@example.test", Password: authtest.Password}).AccessToken
	redeem := func(client *authkit.Client, token string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]string{"code": second.Code})
		req := httptest.NewRequest(http.MethodPost, client.APIBase()+"/invitations/redeem", strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		client.Handler().ServeHTTP(w, req)
		return w
	}
	wrong = redeem(views[0], aToken)
	require.GreaterOrEqual(t, wrong.Code, 400)
	require.Less(t, wrong.Code, 500)
	good = redeem(shared, result.TokenSet.AccessToken)
	require.Equal(t, http.StatusNotFound, good.Code, "registration without contact proof must not accept an addressed invitation")
	second, err = views[1].CreateInvitation(t.Context(), iam.SystemIdentity(), group, iam.NewInvitation{Email: "seed@example.test"})
	require.NoError(t, err)
	foreignSeed, err := views[0].CreateUser(t.Context(), iam.NewUser{Email: "seed@example.test", Username: "foreignseed", Password: authtest.Password, EmailVerified: true})
	require.NoError(t, err)
	foreignToken := authtest.SignIn(t, views[0], authtest.User{User: foreignSeed, Email: "seed@example.test", Password: authtest.Password})
	wrong = redeem(views[0], foreignToken.AccessToken)
	require.GreaterOrEqual(t, wrong.Code, 400)
	require.Less(t, wrong.Code, 500)
	signedIn := authtest.SignIn(t, views[1], authtest.User{User: bSeed, Email: "seed@example.test", Password: authtest.Password})
	good = redeem(shared, signedIn.AccessToken)
	require.Equal(t, http.StatusOK, good.Code)
	held, err = views[1].GroupRoles(t.Context(), group, []iam.Subject{iam.UserSubject(bSeed.ID)})
	require.NoError(t, err)
	require.True(t, held[iam.UserSubject(bSeed.ID)].IsZero())
}
