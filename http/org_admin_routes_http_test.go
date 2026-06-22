package authhttp

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	core "github.com/open-rails/authkit/core"
	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/stretchr/testify/require"
)

// newOrgAdminRoutesHarness spins up a real server + core service backed by the
// test DB. Used by the /admin/orgs/* route tests below. Returns the core
// service, the running server, and a unique slug/username prefix for cleanup.
func newOrgAdminRoutesHarness(t *testing.T) (*core.Service, *httptest.Server, string) {
	t.Helper()
	pool := remoteApplicationBoundaryPG(t)
	prefix := fmt.Sprintf("org-admin-%d", time.Now().UnixNano())

	signer, err := jwtkit.NewRSASigner(2048, "org-admin")
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
		ctx := context.Background()
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.platform_user_roles ur USING profiles.users u WHERE ur.user_id = u.id AND u.username LIKE $1`, prefix+"%")
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.platform_roles WHERE role LIKE $1`, prefix+"%")
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.org_memberships m USING profiles.orgs o WHERE m.org_id = o.id AND o.slug LIKE $1`, prefix+"%")
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.org_role_permissions rp USING profiles.orgs o WHERE rp.org_id = o.id AND o.slug LIKE $1`, prefix+"%")
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.org_roles ro USING profiles.orgs o WHERE ro.org_id = o.id AND o.slug LIKE $1`, prefix+"%")
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug LIKE $1`, prefix+"%")
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username LIKE $1`, prefix+"%")
	})
	return coreSvc, server, prefix
}

// TestAdminOrgsRenameHTTP: a platform admin with platform:orgs:update can rename
// any org (no 72h cooldown), and a caller lacking the perm gets 403.
func TestAdminOrgsRenameHTTP(t *testing.T) {
	ctx := context.Background()
	coreSvc, server, prefix := newOrgAdminRoutesHarness(t)

	superU := createBoundaryUser(t, ctx, coreSvc, prefix+"-super")
	regularU := createBoundaryUser(t, ctx, coreSvc, prefix+"-regular")
	require.NoError(t, coreSvc.EnsurePlatformSuperAdmin(ctx, superU.ID))
	superTok := issueBoundaryUserToken(t, ctx, coreSvc, superU)
	regularTok := issueBoundaryUserToken(t, ctx, coreSvc, regularU)

	org, err := coreSvc.CreateOrgForUser(ctx, core.CreateOrgForUserRequest{Slug: prefix + "-rename-src", OwnerUserID: regularU.ID})
	require.NoError(t, err)

	req := func(method, path, token string, body any) (int, string) {
		return remoteApplicationBoundaryRequestPath(t, server.URL, path, method, token, body)
	}

	// Gate: a regular user lacking platform:orgs:update → 403.
	status, body := req(http.MethodPost, "/admin/orgs/"+org.ID+"/rename", regularTok, map[string]any{"new_slug": prefix + "-rename-dst"})
	require.Equal(t, http.StatusForbidden, status, body)

	// Super-admin renames it; response carries the new canonical slug.
	newSlug := prefix + "-rename-dst"
	status, body = req(http.MethodPost, "/admin/orgs/"+org.ID+"/rename", superTok, map[string]any{"new_slug": newSlug})
	require.Equal(t, http.StatusOK, status, body)
	require.Contains(t, body, newSlug)

	resolved, err := coreSvc.ResolveOrgByID(ctx, org.ID)
	require.NoError(t, err)
	require.Equal(t, newSlug, resolved.Slug)

	// Renaming a non-existent org → 404.
	status, body = req(http.MethodPost, "/admin/orgs/00000000-0000-0000-0000-000000000000/rename", superTok, map[string]any{"new_slug": prefix + "-missing"})
	require.Equal(t, http.StatusNotFound, status, body)
}

// TestAdminOrgsTransferOwnerHTTP: platform:orgs:update reassigns the org owner
// surgically — the prior owner is demoted, the new owner gets org:* — and a
// caller lacking the perm gets 403. The rest of the team is untouched.
func TestAdminOrgsTransferOwnerHTTP(t *testing.T) {
	ctx := context.Background()
	coreSvc, server, prefix := newOrgAdminRoutesHarness(t)

	superU := createBoundaryUser(t, ctx, coreSvc, prefix+"-super")
	oldOwner := createBoundaryUser(t, ctx, coreSvc, prefix+"-oldowner")
	newOwner := createBoundaryUser(t, ctx, coreSvc, prefix+"-newowner")
	regularU := createBoundaryUser(t, ctx, coreSvc, prefix+"-regular")
	require.NoError(t, coreSvc.EnsurePlatformSuperAdmin(ctx, superU.ID))
	superTok := issueBoundaryUserToken(t, ctx, coreSvc, superU)
	regularTok := issueBoundaryUserToken(t, ctx, coreSvc, regularU)

	org, err := coreSvc.CreateOrgForUser(ctx, core.CreateOrgForUserRequest{Slug: prefix + "-transfer-org", OwnerUserID: oldOwner.ID})
	require.NoError(t, err)

	req := func(method, path, token string, body any) (int, string) {
		return remoteApplicationBoundaryRequestPath(t, server.URL, path, method, token, body)
	}

	// Gate: regular user lacking platform:orgs:update → 403.
	status, body := req(http.MethodPost, "/admin/orgs/"+org.ID+"/transfer-owner", regularTok, map[string]any{"new_owner_user_id": newOwner.ID})
	require.Equal(t, http.StatusForbidden, status, body)

	// Unknown new owner → 404 user_not_found.
	status, body = req(http.MethodPost, "/admin/orgs/"+org.ID+"/transfer-owner", superTok, map[string]any{"new_owner_user_id": "00000000-0000-0000-0000-000000000000"})
	require.Equal(t, http.StatusNotFound, status, body)
	require.Contains(t, body, "user_not_found")

	// Unknown org → 404 org_not_found.
	status, body = req(http.MethodPost, "/admin/orgs/00000000-0000-0000-0000-000000000000/transfer-owner", superTok, map[string]any{"new_owner_user_id": newOwner.ID})
	require.Equal(t, http.StatusNotFound, status, body)
	require.Contains(t, body, "org_not_found")

	// Super-admin transfers ownership: prior owner demoted, new owner holds org:*.
	status, body = req(http.MethodPost, "/admin/orgs/"+org.ID+"/transfer-owner", superTok, map[string]any{"new_owner_user_id": newOwner.ID})
	require.Equal(t, http.StatusOK, status, body)

	newPerms, err := coreSvc.EffectivePermissions(ctx, org.Slug, newOwner.ID)
	require.NoError(t, err)
	require.Contains(t, newPerms, core.PermOrgMembersCreate)

	// Prior owner was demoted to plain member (no owner authority).
	oldPerms, err := coreSvc.EffectivePermissions(ctx, org.Slug, oldOwner.ID)
	require.NoError(t, err)
	require.NotContains(t, oldPerms, core.PermOrgMembersCreate)
}

// TestAdminOrgsDeletedListHTTP: GET /admin/orgs/deleted returns only soft-deleted
// orgs, gated on platform:orgs:read; a caller without the perm gets 403.
func TestAdminOrgsDeletedListHTTP(t *testing.T) {
	ctx := context.Background()
	coreSvc, server, prefix := newOrgAdminRoutesHarness(t)

	superU := createBoundaryUser(t, ctx, coreSvc, prefix+"-super")
	regularU := createBoundaryUser(t, ctx, coreSvc, prefix+"-regular")
	require.NoError(t, coreSvc.EnsurePlatformSuperAdmin(ctx, superU.ID))
	superTok := issueBoundaryUserToken(t, ctx, coreSvc, superU)
	regularTok := issueBoundaryUserToken(t, ctx, coreSvc, regularU)

	liveOrg, err := coreSvc.CreateOrgForUser(ctx, core.CreateOrgForUserRequest{Slug: prefix + "-deleted-live", OwnerUserID: regularU.ID})
	require.NoError(t, err)
	deletedOrg, err := coreSvc.CreateOrgForUser(ctx, core.CreateOrgForUserRequest{Slug: prefix + "-deleted-gone", OwnerUserID: regularU.ID})
	require.NoError(t, err)
	removed, err := coreSvc.SoftDeleteOrg(ctx, deletedOrg.ID)
	require.NoError(t, err)
	require.True(t, removed)

	req := func(method, path, token string, body any) (int, string) {
		return remoteApplicationBoundaryRequestPath(t, server.URL, path, method, token, body)
	}

	// Gate: a regular user lacking platform:orgs:read → 403.
	status, body := req(http.MethodGet, "/admin/orgs/deleted?search="+prefix, regularTok, nil)
	require.Equal(t, http.StatusForbidden, status, body)

	// Super-admin: the deleted view contains the soft-deleted org and NOT the live one.
	status, body = req(http.MethodGet, "/admin/orgs/deleted?search="+prefix, superTok, nil)
	require.Equal(t, http.StatusOK, status, body)
	var resp struct {
		Orgs []struct {
			ID        string  `json:"id"`
			Slug      string  `json:"slug"`
			DeletedAt *string `json:"deleted_at"`
		} `json:"orgs"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &resp))
	var sawDeleted, sawLive bool
	for _, o := range resp.Orgs {
		if o.ID == deletedOrg.ID {
			sawDeleted = true
			require.NotNil(t, o.DeletedAt)
		}
		if o.ID == liveOrg.ID {
			sawLive = true
		}
	}
	require.True(t, sawDeleted, "deleted org should appear in /admin/orgs/deleted")
	require.False(t, sawLive, "live org must NOT appear in /admin/orgs/deleted")
}

// TestAdminOrgsSlugLifecycleRelocatedHTTP proves the slug lifecycle now lives at
// /admin/orgs/* (gated on platform:orgs:reserved-names), the old /admin/account(s)/*
// paths are GONE (404), and a caller without the perm gets 403.
func TestAdminOrgsSlugLifecycleRelocatedHTTP(t *testing.T) {
	ctx := context.Background()
	coreSvc, server, prefix := newOrgAdminRoutesHarness(t)

	superU := createBoundaryUser(t, ctx, coreSvc, prefix+"-super")
	limitedU := createBoundaryUser(t, ctx, coreSvc, prefix+"-limited")
	regularU := createBoundaryUser(t, ctx, coreSvc, prefix+"-regular")
	require.NoError(t, coreSvc.EnsurePlatformSuperAdmin(ctx, superU.ID))
	// A least-privilege admin holding ONLY platform:orgs:read (NOT reserved-names).
	roRole := prefix + "-orgs-read-role"
	require.NoError(t, coreSvc.DefinePlatformRole(ctx, roRole))
	require.NoError(t, coreSvc.SetPlatformRolePermissions(ctx, roRole, []string{core.PermPlatformOrgsRead}))
	require.NoError(t, coreSvc.AssignPlatformRole(ctx, limitedU.ID, roRole))

	superTok := issueBoundaryUserToken(t, ctx, coreSvc, superU)
	limitedTok := issueBoundaryUserToken(t, ctx, coreSvc, limitedU)
	regularTok := issueBoundaryUserToken(t, ctx, coreSvc, regularU)

	req := func(method, path, token string, body any) (int, string) {
		return remoteApplicationBoundaryRequestPath(t, server.URL, path, method, token, body)
	}

	slug := prefix + "-reserved"

	// Gate: regular user and read-only admin both lack platform:orgs:reserved-names → 403.
	status, body := req(http.MethodPost, "/admin/orgs/restrict", regularTok, map[string]any{"slugs": []string{slug}})
	require.Equal(t, http.StatusForbidden, status, body)
	status, body = req(http.MethodPost, "/admin/orgs/restrict", limitedTok, map[string]any{"slugs": []string{slug}})
	require.Equal(t, http.StatusForbidden, status, body)

	// Super-admin (platform:*) can drive the full lifecycle at the new home.
	status, body = req(http.MethodPost, "/admin/orgs/restrict", superTok, map[string]any{"slugs": []string{slug}})
	require.Equal(t, http.StatusOK, status, body)
	require.Contains(t, body, slug)
	t.Cleanup(func() {
		_, _ = req(http.MethodPost, "/admin/orgs/unrestrict", superTok, map[string]any{"slugs": []string{slug}})
	})

	status, body = req(http.MethodPost, "/admin/orgs/unrestrict", superTok, map[string]any{"slugs": []string{slug}})
	require.Equal(t, http.StatusOK, status, body)

	// park (kind: org) reserves the slug as a parked org.
	parkSlug := prefix + "-parked"
	status, body = req(http.MethodPost, "/admin/orgs/park", superTok, map[string]any{"kind": "org", "slug": parkSlug})
	require.Equal(t, http.StatusOK, status, body)

	// claim (kind: org) hands the parked org to the rightful owner.
	status, body = req(http.MethodPost, "/admin/orgs/claim", superTok, map[string]any{"kind": "org", "slug": parkSlug, "owner_user_id": regularU.ID})
	require.Equal(t, http.StatusOK, status, body)

	// The OLD /admin/account(s)/* paths are gone entirely (404) even for super-admin.
	for _, p := range []string{
		"/admin/accounts/restrict",
		"/admin/accounts/unrestrict",
		"/admin/account/park",
		"/admin/account/claim",
	} {
		status, body = req(http.MethodPost, p, superTok, map[string]any{"slugs": []string{slug}})
		require.Equal(t, http.StatusNotFound, status, p+": "+body)
	}
}

// TestAdminOrgsNoCreateRoute confirms there is NO platform org-create route:
// org creation is self-service only (POST /orgs), never an admin mint.
func TestAdminOrgsNoCreateRoute(t *testing.T) {
	ctx := context.Background()
	coreSvc, server, prefix := newOrgAdminRoutesHarness(t)
	superU := createBoundaryUser(t, ctx, coreSvc, prefix+"-super")
	require.NoError(t, coreSvc.EnsurePlatformSuperAdmin(ctx, superU.ID))
	superTok := issueBoundaryUserToken(t, ctx, coreSvc, superU)

	// POST /admin/orgs has no handler — even the super-admin gets 404/405, never 200.
	status, body := remoteApplicationBoundaryRequestPath(t, server.URL, "/admin/orgs", http.MethodPost, superTok, map[string]any{"slug": prefix + "-minted"})
	require.NotEqual(t, http.StatusOK, status, body)
	require.True(t, status == http.StatusNotFound || status == http.StatusMethodNotAllowed, "expected 404/405 for admin org-create, got %d: %s", status, body)
}
