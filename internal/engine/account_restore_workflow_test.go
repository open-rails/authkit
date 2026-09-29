package engine

import (
	"net/http"
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestStaffAccountRestoreHTTPRequiresCurrentAuthority(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.TwoFactor.Mode = iam.TwoFactorDisabled
	cfg.Roles = RoleConfig{Roles: []Role{{Persona: "root", Name: "staff", Permissions: []string{iam.PermRootUsersDelete.String()}}}}
	f := newAccountFlow(t, pg.Pool, cfg)
	register := func(name string) (iam.TokenSet, string) {
		t.Helper()
		response := f.expect(http.StatusAccepted, f.post("/register", map[string]any{"identifier": name + "@example.test", "username": name, "password": "Correct-horse-account-recovery-1"}))
		claims, err := f.service.Verifier().Verify(t.Context(), response.Tokens.AccessToken)
		require.NoError(t, err)
		return response.Tokens, claims.UserID
	}
	staff, staffID := register("restorestaff")
	target, targetID := register("restoretarget")
	grantRole(t, fixtureBackend(f.service.Backend()), iam.RootGroup(), iam.UserSubject(staffID), "staff")
	path := "/admin/users/" + targetID
	f.expect(http.StatusNoContent, f.request(http.MethodDelete, path, staff.AccessToken, nil))
	f.expect(http.StatusUnauthorized, f.request(http.MethodPost, path+"/restore", "", nil))
	refused := f.expect(http.StatusUnauthorized, f.request(http.MethodPost, path+"/restore", target.AccessToken, nil))
	require.Equal(t, "session_revoked", refused.Error.Code, "the deletion ended the target's own session")
	f.expect(http.StatusNoContent, f.request(http.MethodPost, path+"/restore", staff.AccessToken, nil))
	user, err := fixtureBackend(f.service.Backend()).getUserByID(t.Context(), targetID)
	require.NoError(t, err)
	require.Nil(t, user.DeletedAt)
	f.expect(http.StatusUnauthorized, f.post("/token", map[string]any{"grant_type": "refresh_token", "refresh_token": target.RefreshToken}))
	f.expect(http.StatusNoContent, f.request(http.MethodDelete, path, staff.AccessToken, nil))
	revokeRole(t, fixtureBackend(f.service.Backend()), iam.RootGroup(), iam.UserSubject(staffID), "staff")
	f.expect(http.StatusForbidden, f.request(http.MethodPost, path+"/restore", staff.AccessToken, nil))
	user, err = fixtureBackend(f.service.Backend()).getUserByID(t.Context(), targetID)
	require.NoError(t, err)
	require.NotNil(t, user.DeletedAt, "revocation is immediate even for a previously accepted staff token")
	f.expect(http.StatusNotFound, f.request(http.MethodGet, "/admin/erasure/backlog", staff.AccessToken, nil))
}
