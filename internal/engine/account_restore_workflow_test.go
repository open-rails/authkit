package engine

import (
	"net/http"
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestOperatorAccountRestoreHTTPRequiresCurrentAuthority(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.TwoFactor.Mode = iam.TwoFactorDisabled
	cfg.Roles = RoleConfig{Roles: []Role{{Persona: iam.RootPersona, Name: "operator", Permissions: []string{iam.PermRootUsersDelete}}}}
	f := newAccountFlow(t, pg.Pool, cfg)
	register := func(name string) (iam.TokenSet, string) {
		t.Helper()
		response := f.expect(http.StatusAccepted, f.post("/register", map[string]any{"identifier": name + "@example.test", "username": name, "password": "Correct-horse-account-recovery-1"}))
		claims, err := f.service.Verifier().Verify(t.Context(), response.Tokens.AccessToken)
		require.NoError(t, err)
		return response.Tokens, claims.UserID
	}
	operator, operatorID := register("restoreoperator")
	target, targetID := register("restoretarget")
	grantRole(t, fixtureBackend(f.service.Backend()), iam.RootGroup(), iam.UserSubject(operatorID), "operator")
	path := "/admin/users/" + targetID
	f.expect(http.StatusNoContent, f.request(http.MethodDelete, path, operator.AccessToken, nil))
	f.expect(http.StatusUnauthorized, f.request(http.MethodPost, path+"/restore", "", nil))
	f.expect(http.StatusForbidden, f.request(http.MethodPost, path+"/restore", target.AccessToken, nil))
	f.expect(http.StatusNoContent, f.request(http.MethodPost, path+"/restore", operator.AccessToken, nil))
	user, err := fixtureBackend(f.service.Backend()).getUserByID(t.Context(), targetID)
	require.NoError(t, err)
	require.Nil(t, user.DeletedAt)
	f.expect(http.StatusUnauthorized, f.post("/token", map[string]any{"grant_type": "refresh_token", "refresh_token": target.RefreshToken}))
	f.expect(http.StatusNoContent, f.request(http.MethodDelete, path, operator.AccessToken, nil))
	revokeRole(t, fixtureBackend(f.service.Backend()), iam.RootGroup(), iam.UserSubject(operatorID), "operator")
	f.expect(http.StatusForbidden, f.request(http.MethodPost, path+"/restore", operator.AccessToken, nil))
	user, err = fixtureBackend(f.service.Backend()).getUserByID(t.Context(), targetID)
	require.NoError(t, err)
	require.NotNil(t, user.DeletedAt, "revocation is immediate even for a previously accepted operator token")
	f.expect(http.StatusNotFound, f.request(http.MethodGet, "/admin/erasure/backlog", operator.AccessToken, nil))
}
