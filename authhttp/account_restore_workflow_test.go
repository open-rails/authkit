package authhttp

import (
	"net/http"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestOperatorAccountRestoreHTTPRequiresCurrentAuthority(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.TwoFactor.Mode = embedded.TwoFactorDisabled
	cfg.RBAC = []embedded.PersonaDef{embedded.IntrinsicRootPersona(embedded.RoleDef{Name: "operator", Permissions: []string{embedded.PermRootUsersDelete, embedded.PermRootUsersRecover}})}
	f := newAccountFlow(t, pg.Pool, cfg)
	register := func(name string) (authkit.TokenSet, string) {
		t.Helper()
		response := f.expect(http.StatusAccepted, f.post("/register", map[string]any{"identifier": name + "@example.test", "username": name, "password": "Correct-horse-account-recovery-1"}))
		claims, err := f.service.Verifier().Verify(t.Context(), response.Tokens.AccessToken)
		require.NoError(t, err)
		return response.Tokens, claims.UserID
	}
	operator, operatorID := register("restoreoperator")
	target, targetID := register("restoretarget")
	require.NoError(t, f.service.svc.OperatorAssignGroupRole(t.Context(), authkit.RootGroup(), authkit.UserSubject(operatorID), "operator"))
	path := "/admin/users/" + targetID
	f.expect(http.StatusNoContent, f.request(http.MethodDelete, path, operator.AccessToken, nil))
	f.expect(http.StatusUnauthorized, f.request(http.MethodPost, path+"/restore", "", nil))
	f.expect(http.StatusForbidden, f.request(http.MethodPost, path+"/restore", target.AccessToken, nil))
	f.expect(http.StatusNoContent, f.request(http.MethodPost, path+"/restore", operator.AccessToken, nil))
	user, err := f.service.svc.AdminGetUser(t.Context(), targetID)
	require.NoError(t, err)
	require.Nil(t, user.DeletedAt)
	f.expect(http.StatusUnauthorized, f.post("/token", map[string]any{"grant_type": "refresh_token", "refresh_token": target.RefreshToken}))
	f.expect(http.StatusNoContent, f.request(http.MethodDelete, path, operator.AccessToken, nil))
	require.NoError(t, f.service.svc.OperatorUnassignGroupRole(t.Context(), authkit.RootGroup(), authkit.UserSubject(operatorID), "operator"))
	f.expect(http.StatusForbidden, f.request(http.MethodPost, path+"/restore", operator.AccessToken, nil))
	user, err = f.service.svc.AdminGetUser(t.Context(), targetID)
	require.NoError(t, err)
	require.NotNil(t, user.DeletedAt, "revocation is immediate even for a previously accepted operator token")
	f.expect(http.StatusNotFound, f.request(http.MethodGet, "/admin/erasure/backlog", operator.AccessToken, nil))
}
