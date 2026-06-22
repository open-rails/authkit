package authhttp

import (
	"context"
	"crypto"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	core "github.com/open-rails/authkit/core"
	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/stretchr/testify/require"
)

// TestAdminPlatformGateHTTP exercises the hard-cut of the /admin/* surface from
// the legacy global-admin gate to Layer-2 platform RBAC (#95). The gate is now
// requirePlatformPermission (authenticated + holds a specific `platform:` perm,
// with NO global-admin bypass). A real server + real bearer tokens assert the
// gate across unauthenticated, regular-user, super-admin, and a least-privilege
// platform-admin holding only platform:users:read. Skips without
// AUTHKIT_TEST_DATABASE_URL.
func TestAdminPlatformGateHTTP(t *testing.T) {
	pool := remoteApplicationBoundaryPG(t)
	ctx := context.Background()
	prefix := fmt.Sprintf("admin-gate-%d", time.Now().UnixNano())

	signer, err := jwtkit.NewRSASigner(2048, "admin-gate")
	require.NoError(t, err)
	coreSvc := core.NewService(core.Options{
		Issuer:                   "https://" + prefix + ".authkit.test",
		IssuedAudiences:          []string{"plat"},
		ExpectedAudiences:        []string{"plat"},
		AccessTokenDuration:      time.Hour,
		RegistrationVerification: core.RegistrationVerificationNone,
		APIKeyPrefix:             "authkit",
	}, core.Keyset{
		Active:     signer,
		PublicKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
	}, core.WithPostgres(pool))
	verifier := NewVerifier(WithSkew(5 * time.Second)).WithService(coreSvc)
	require.NoError(t, verifier.AddIssuer(coreSvc.Options().Issuer, coreSvc.Options().ExpectedAudiences, IssuerOptions{
		RawKeys: coreSvc.PublicKeysByKID(),
	}))
	svc := &Service{svc: coreSvc, verifier: verifier}
	server := httptest.NewServer(svc.APIHandler())
	t.Cleanup(server.Close)

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.platform_user_roles ur USING profiles.users u WHERE ur.user_id = u.id AND u.username LIKE $1`, prefix+"%")
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.platform_roles WHERE role LIKE $1`, prefix+"%")
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.owner_reserved_names WHERE slug LIKE $1`, prefix+"%")
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.users WHERE username LIKE $1`, prefix+"%")
	})

	superU := createBoundaryUser(t, ctx, coreSvc, prefix+"-super")
	limitedU := createBoundaryUser(t, ctx, coreSvc, prefix+"-limited")
	regularU := createBoundaryUser(t, ctx, coreSvc, prefix+"-regular")

	// Bootstrap the first super-admin out-of-band (platform:*).
	require.NoError(t, coreSvc.EnsurePlatformSuperAdmin(ctx, superU.ID))

	// A least-privilege platform-admin holding ONLY platform:users:read.
	limitedRole := prefix + "-readonly-role"
	require.NoError(t, coreSvc.DefinePlatformRole(ctx, limitedRole))
	require.NoError(t, coreSvc.SetPlatformRolePermissions(ctx, limitedRole, []string{core.PermPlatformUsersRead}))
	require.NoError(t, coreSvc.AssignPlatformRole(ctx, limitedU.ID, limitedRole))

	superTok := issueBoundaryUserToken(t, ctx, coreSvc, superU)
	limitedTok := issueBoundaryUserToken(t, ctx, coreSvc, limitedU)
	regularTok := issueBoundaryUserToken(t, ctx, coreSvc, regularU)
	req := func(method, path, token string, body any) (int, string) {
		return remoteApplicationBoundaryRequestPath(t, server.URL, path, method, token, body)
	}

	// 1. GET /admin/users with NO token → 401 (gate requires authentication).
	status, body := req(http.MethodGet, "/admin/users", "", nil)
	require.Equal(t, http.StatusUnauthorized, status, body)

	// 2. Regular user (no platform role) → 403: no global-admin bypass exists.
	status, body = req(http.MethodGet, "/admin/users", regularTok, nil)
	require.Equal(t, http.StatusForbidden, status, body)

	// 3. Super-admin (platform:*) → 200.
	status, body = req(http.MethodGet, "/admin/users", superTok, nil)
	require.Equal(t, http.StatusOK, status, body)

	// 4. Least-privilege platform-admin holding ONLY platform:users:read:
	//    can read the directory, but cannot ban (lacks platform:users:ban).
	status, body = req(http.MethodGet, "/admin/users", limitedTok, nil)
	require.Equal(t, http.StatusOK, status, body)
	status, body = req(http.MethodPost, "/admin/users/ban", limitedTok, map[string]any{"user_id": regularU.ID})
	require.Equal(t, http.StatusForbidden, status, body)

	// 5. POST /admin/orgs/restrict needs platform:orgs:reserved-names (relocated
	//    from the old /admin/accounts/restrict): regular user → 403; super-admin → 200.
	status, body = req(http.MethodPost, "/admin/orgs/restrict", regularTok, map[string]any{"slugs": []string{prefix + "-sometestslug"}})
	require.Equal(t, http.StatusForbidden, status, body)
	status, body = req(http.MethodPost, "/admin/orgs/restrict", superTok, map[string]any{"slugs": []string{prefix + "-sometestslug"}})
	require.Equal(t, http.StatusOK, status, body)

	// 6. The OLD /admin/account(s)/* paths are gone entirely (relocated to
	//    /admin/orgs/*). Even the super-admin gets 404 — the routes no longer exist.
	for _, p := range []string{"/admin/accounts/restrict", "/admin/accounts/unrestrict", "/admin/account/park", "/admin/account/claim"} {
		status, body = req(http.MethodPost, p, superTok, map[string]any{"slugs": []string{prefix + "-x"}})
		require.Equal(t, http.StatusNotFound, status, p+": "+body)
	}
}
