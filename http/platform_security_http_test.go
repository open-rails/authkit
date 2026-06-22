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

// TestPlatformSecurityHTTP is the end-to-end security test for the Layer-2
// platform RBAC HTTP surface (#95): a real server + real bearer tokens exercise
// the gate (unauthenticated / regular-user / platform-admin), the DISJOINT
// namespace rule, NO-ESCALATION on platform grants, and the `recover`
// authorization. Skips without AUTHKIT_TEST_DATABASE_URL.
func TestPlatformSecurityHTTP(t *testing.T) {
	pool := remoteApplicationBoundaryPG(t)
	ctx := context.Background()
	prefix := fmt.Sprintf("plat-sec-%d", time.Now().UnixNano())

	signer, err := jwtkit.NewRSASigner(2048, "plat-sec")
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
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.orgs WHERE slug LIKE $1`, prefix+"%")
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.users WHERE username LIKE $1`, prefix+"%")
	})

	superU := createBoundaryUser(t, ctx, coreSvc, prefix+"-super")
	limitedU := createBoundaryUser(t, ctx, coreSvc, prefix+"-limited")
	regularU := createBoundaryUser(t, ctx, coreSvc, prefix+"-regular")

	// Bootstrap the first super-admin out-of-band (platform:*).
	require.NoError(t, coreSvc.EnsurePlatformSuperAdmin(ctx, superU.ID))

	// A LIMITED platform-admin: can read/define roles + grant members, but does
	// NOT hold platform:users:ban or platform:orgs:recover.
	limitedRole := prefix + "-limited-role"
	require.NoError(t, coreSvc.DefinePlatformRole(ctx, limitedRole))
	require.NoError(t, coreSvc.SetPlatformRolePermissions(ctx, limitedRole, []string{
		core.PermPlatformUsersRead, core.PermPlatformRolesRead, core.PermPlatformRolesCreate, core.PermPlatformMembersCreate,
	}))
	require.NoError(t, coreSvc.AssignPlatformRole(ctx, limitedU.ID, limitedRole))

	superTok := issueBoundaryUserToken(t, ctx, coreSvc, superU)
	superSessionID, _, _, err := coreSvc.IssueRefreshSession(ctx, superU.ID, "platform-security-test", nil)
	require.NoError(t, err)
	superFreshTok := issueBoundaryUserTokenWithSession(t, ctx, coreSvc, superU, superSessionID)
	limitedTok := issueBoundaryUserToken(t, ctx, coreSvc, limitedU)
	regularTok := issueBoundaryUserToken(t, ctx, coreSvc, regularU)
	req := func(method, path, token string, body any) (int, string) {
		return remoteApplicationBoundaryRequestPath(t, server.URL, path, method, token, body)
	}

	// 1. Unauthenticated → 401.
	status, body := req(http.MethodGet, "/admin/platform-roles", "", nil)
	require.Equal(t, http.StatusUnauthorized, status, body)

	// 2. Regular user (no platform role) → 403: the gate denies non-admins.
	status, body = req(http.MethodGet, "/admin/platform-roles", regularTok, nil)
	require.Equal(t, http.StatusForbidden, status, body)

	// 3. Super-admin → 200.
	status, body = req(http.MethodGet, "/admin/platform-roles", superTok, nil)
	require.Equal(t, http.StatusOK, status, body)

	// 4. Self-introspection: regular has none; super-admin sees platform:* expanded.
	status, body = req(http.MethodGet, "/me/platform-permissions", regularTok, nil)
	require.Equal(t, http.StatusOK, status, body)
	require.NotContains(t, body, "platform:")
	status, body = req(http.MethodGet, "/me/platform-permissions", superTok, nil)
	require.Equal(t, http.StatusOK, status, body)
	require.Contains(t, body, "platform:orgs:recover")

	// 5. DISJOINT: a platform role cannot hold an `org:` perm → 400 unknown_permission.
	status, body = req(http.MethodPut, "/admin/platform-roles/"+prefix+"-disjoint", superTok, map[string]any{
		"permissions": []string{"org:members:read"},
	})
	require.Equal(t, http.StatusBadRequest, status, body)
	require.Contains(t, body, "unknown_permission")

	// 6. NO-ESCALATION: the limited admin (no platform:users:ban) cannot mint a
	//    role granting it → 403 permission_grant_denied.
	status, body = req(http.MethodPut, "/admin/platform-roles/"+prefix+"-escalate", limitedTok, map[string]any{
		"permissions": []string{core.PermPlatformUsersBan},
	})
	require.Equal(t, http.StatusForbidden, status, body)
	require.Contains(t, body, "permission_grant_denied")

	// ...but the limited admin CAN define a role with a perm they hold.
	status, body = req(http.MethodPut, "/admin/platform-roles/"+prefix+"-ok", limitedTok, map[string]any{
		"permissions": []string{core.PermPlatformUsersRead},
	})
	require.Equal(t, http.StatusOK, status, body)

	// 7. RECOVER authorization: needs platform:orgs:recover specifically.
	org, err := coreSvc.CreateOrgForUser(ctx, core.CreateOrgForUserRequest{Slug: prefix + "-recover-org", OwnerUserID: regularU.ID})
	require.NoError(t, err)
	// limited admin lacks platform:orgs:recover → 403.
	status, body = req(http.MethodPost, "/admin/orgs/"+org.ID+"/recover", limitedTok, map[string]any{"new_owner_user_id": superU.ID})
	require.Equal(t, http.StatusForbidden, status, body)
	_, err = pool.Exec(ctx, `UPDATE profiles.refresh_sessions SET last_authenticated_at = now() - interval '1 hour' WHERE id = $1`, superSessionID)
	require.NoError(t, err)
	// super-admin holds it, but stale session freshness blocks the sensitive action.
	status, body = req(http.MethodPost, "/admin/orgs/"+org.ID+"/recover", superFreshTok, map[string]any{"new_owner_user_id": superU.ID})
	require.Equal(t, http.StatusForbidden, status, body)
	require.Contains(t, body, "reauth_required")
	require.NoError(t, coreSvc.MarkSessionAuthenticated(ctx, superU.ID, superSessionID))
	// super-admin with fresh session → 200, and the org is reset to the new owner.
	status, body = req(http.MethodPost, "/admin/orgs/"+org.ID+"/recover", superFreshTok, map[string]any{"new_owner_user_id": superU.ID})
	require.Equal(t, http.StatusOK, status, body)

	// The recovered owner now holds full org authority; the prior owner is demoted.
	superOrgPerms, err := coreSvc.EffectivePermissions(ctx, org.Slug, superU.ID)
	require.NoError(t, err)
	require.Contains(t, superOrgPerms, core.PermOrgMembersCreate)
	priorPerms, err := coreSvc.EffectivePermissions(ctx, org.Slug, regularU.ID)
	require.NoError(t, err)
	require.Empty(t, priorPerms)
}
