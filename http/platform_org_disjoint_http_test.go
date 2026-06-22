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

// TestPlatformAdminCannotReachOrgInternalsHTTP proves the #95 DISJOINT-planes
// invariant at the HTTP layer: a strong PLATFORM role (super-admin = platform:*)
// grants ZERO authority INSIDE an org. A platform admin manages orgs as ENTITIES
// (via /admin/orgs/*); the only sanctioned reach inside an org is the coarse
// platform:orgs:recover break-glass — NOT day-to-day members/roles/api-keys, not
// even read-only. The org-internal gate (requireOrgPermission) is org-MEMBERSHIP
// only, with no platform/global-admin bypass.
//
// This test asserts:
//   - A super-admin (platform:*) who is NOT a member of org X gets 403 on the
//     org-internal routes GET/POST /orgs/{X}/members, GET /orgs/{X}/roles,
//     GET /orgs/{X}/api-keys. Platform authority does NOT satisfy the org: gate.
//   - The org's actual owner (holding org:*) gets 200 on those same routes,
//     proving the routes work and it is specifically platform-authority excluded.
//   - There is no "platform admin acting as a user" surface; the membership
//     denial above is the operative proof (see the impersonation note below).
//
// Skips without AUTHKIT_TEST_DATABASE_URL.
func TestPlatformAdminCannotReachOrgInternalsHTTP(t *testing.T) {
	pool := remoteApplicationBoundaryPG(t)
	ctx := context.Background()
	prefix := fmt.Sprintf("plat-disjoint-%d", time.Now().UnixNano())

	signer, err := jwtkit.NewRSASigner(2048, "plat-disjoint")
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

	// superU holds platform:* (the strongest platform role) but is NOT a member
	// of orgX. ownerX is orgX's actual owner (holds org:*).
	superU := createBoundaryUser(t, ctx, coreSvc, prefix+"-super")
	ownerX := createBoundaryUser(t, ctx, coreSvc, prefix+"-owner-x")
	outsiderU := createBoundaryUser(t, ctx, coreSvc, prefix+"-member-add")

	require.NoError(t, coreSvc.EnsurePlatformSuperAdmin(ctx, superU.ID))

	orgX, err := coreSvc.CreateOrgForUser(ctx, core.CreateOrgForUserRequest{Slug: prefix + "-org-x", OwnerUserID: ownerX.ID})
	require.NoError(t, err)

	// Sanity: the super-admin really holds the apex platform grant, AND really has
	// no authority inside orgX (the precondition that makes the 403s meaningful —
	// it's the platform role being excluded, not a powerless token).
	// EffectivePlatformPermissions EXPANDS the platform:* glob into the concrete
	// catalog, so assert on an expanded entry that only a strong platform role holds.
	superPlatPerms, err := coreSvc.EffectivePlatformPermissions(ctx, superU.ID)
	require.NoError(t, err)
	require.Contains(t, superPlatPerms, core.PermPlatformOrgsRecover)
	superOrgPerms, err := coreSvc.EffectivePermissions(ctx, orgX.Slug, superU.ID)
	require.NoError(t, err)
	require.Empty(t, superOrgPerms, "super-admin must hold NO org: permission inside an org it is not a member of")

	superTok := issueBoundaryUserToken(t, ctx, coreSvc, superU)
	ownerTok := issueBoundaryUserToken(t, ctx, coreSvc, ownerX)
	req := func(method, path, token string, body any) (int, string) {
		return remoteApplicationBoundaryRequestPath(t, server.URL, path, method, token, body)
	}

	base := "/orgs/" + orgX.Slug

	// The org-internal read routes + one mutating route. Every one is gated on an
	// org: permission for the path org; a platform grant must NOT satisfy it.
	readRoutes := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{"members-list", http.MethodGet, base + "/members", nil},
		{"roles-list", http.MethodGet, base + "/roles", nil},
		{"api-keys-list", http.MethodGet, base + "/api-keys", nil},
		{"members-add", http.MethodPost, base + "/members", map[string]any{"user_id": outsiderU.ID}},
	}

	// 1. Platform super-admin (NOT an org member) → 403 on every org-internal
	//    route. Platform authority does NOT cross into an org's internals.
	for _, rt := range readRoutes {
		status, body := req(rt.method, rt.path, superTok, rt.body)
		require.Equalf(t, http.StatusForbidden, status,
			"super-admin (platform:*) must be DENIED org-internal %s: %s", rt.name, body)
	}

	// 2. Contrast: orgX's actual owner (holding org:*) gets 200 on the SAME read
	//    routes — proving the routes work and it is specifically platform-authority
	//    that is excluded above (not a broken route).
	for _, rt := range readRoutes {
		if rt.method != http.MethodGet {
			continue
		}
		status, body := req(rt.method, rt.path, ownerTok, rt.body)
		require.Equalf(t, http.StatusOK, status,
			"orgX owner (org:*) must be ALLOWED org-internal %s: %s", rt.name, body)
	}
	// And the owner can perform the mutating route too (200), where the platform
	// admin got 403 — the cleanest side-by-side proof of the disjoint planes.
	status, body := req(http.MethodPost, base+"/members", ownerTok, map[string]any{"user_id": outsiderU.ID})
	require.Equal(t, http.StatusOK, status, "orgX owner must be ALLOWED to add a member: "+body)

	// 3. "Platform admin acting as a user" surface: there is none. AuthKit has no
	//    impersonation / act-as / token-mint-for-another-user route (the platform
	//    plane administers orgs as ENTITIES and the global account directory, never
	//    mints a session as someone else). Assert the shapes that WOULD be such a
	//    surface are absent (404), so platform authority can never be laundered
	//    into a user identity. The membership denial in (1) is the operative proof.
	for _, p := range []string{
		"/admin/users/" + ownerX.ID + "/impersonate",
		"/admin/users/" + ownerX.ID + "/token",
		"/admin/users/" + ownerX.ID + "/act-as",
	} {
		status, body := req(http.MethodPost, p, superTok, map[string]any{})
		require.Equalf(t, http.StatusNotFound, status,
			"no act-as-user surface may exist (%s) — platform authority must never become a user identity: %s", p, body)
	}
}
