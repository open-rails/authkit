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

// No-escalation regression suite (#94): "you can never grant a permission you do
// not yourself hold." Every grant HTTP handler resolves the role/permission set
// it is about to confer and runs it through ValidateGrant/ValidatePlatformGrant
// before mutating, so a grantor holding a STRICT SUBSET of permissions is
// rejected with 403 (role_exceeds_grantor or permission_grant_denied) while an
// owner (org:*) / super-admin (platform:*) succeeds.
//
// Coverage map (this file + pre-existing tests):
//   1. Remote-app role assignment   — TestNoEscalationRemoteAppRoleAssignHTTP  (THIS FILE, keystone)
//   2. Member-role assign           — TestNoEscalationMemberRoleAssignHTTP      (THIS FILE)
//   3. Role-perm set                — TestNoEscalationRolePermSetHTTP           (THIS FILE)
//   4. API-key mint                 — TestAPIKeyMintRoleAuthorizationHTTP       (api_key_mint_role_http_test.go)
//   5. Org invite                   — TestNoEscalationOrgInviteHTTP (THIS FILE) + core TestOrgInviteNoEscalation
//   6. Platform role assign         — TestNoEscalationPlatformRoleGrantHTTP     (THIS FILE)
//   7. Platform role-perm set       — TestPlatformSecurityHTTP step 6           (platform_security_http_test.go)
//
// All tests skip without AUTHKIT_TEST_DATABASE_URL.

// newGrantPathTestServer spins up a real httptest server backed by the test DB,
// with the given host-app permission catalog declared. Returns the live core
// service and the server.
func newGrantPathTestServer(t *testing.T, prefix string, perms []core.PermissionDef) (*core.Service, *httptest.Server) {
	t.Helper()
	pool := remoteApplicationBoundaryPG(t)
	signer, err := jwtkit.NewRSASigner(2048, prefix)
	require.NoError(t, err)
	coreSvc := core.NewService(core.Options{
		Issuer:                   "https://" + prefix + ".authkit.test",
		IssuedAudiences:          []string{"noesc"},
		ExpectedAudiences:        []string{"noesc"},
		AccessTokenDuration:      time.Hour,
		RegistrationVerification: core.RegistrationVerificationNone,
		APIKeyPrefix:             "authkit",
		Permissions:              perms,
	}, core.Keyset{
		Active:     signer,
		PublicKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
	}).WithPostgres(pool)
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
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.remote_applications WHERE slug LIKE $1`, prefix+"%")
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.orgs WHERE slug LIKE $1`, prefix+"%")
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.users WHERE username LIKE $1`, prefix+"%")
	})
	return coreSvc, server
}

// TestNoEscalationRemoteAppRoleAssignHTTP is the #94 KEYSTONE. It exercises the
// exact hole that was patched: POST /orgs/{org}/remote-applications/{slug}/memberships.
//
// A "remote-app manager" holds ONLY org:remote_applications:* — enough to pass
// BOTH the membership endpoint's gates (authRemoteApplicationBySlug and
// canManageOrgMembership both require org:remote_applications:update, which the
// glob covers) — but NOT org:*. Without the ValidateGrant call this manager could
// assign the `owner` role (=org:*) to a remote-app and escalate it past their own
// authority. The fix makes that 403 role_exceeds_grantor. An org owner (org:*)
// can still assign owner.
//
// This assertion FAILS against the pre-fix handler (which mutated without the
// no-escalation check) and PASSES against the patched handler.
func TestNoEscalationRemoteAppRoleAssignHTTP(t *testing.T) {
	ctx := context.Background()
	prefix := fmt.Sprintf("noesc-ra-%d", time.Now().UnixNano())
	coreSvc, server := newGrantPathTestServer(t, prefix, nil)

	owner := createBoundaryUser(t, ctx, coreSvc, prefix+"-owner")
	manager := createBoundaryUser(t, ctx, coreSvc, prefix+"-manager")
	org, err := coreSvc.CreateOrgForUser(ctx, core.CreateOrgForUserRequest{Slug: prefix + "-org", OwnerUserID: owner.ID})
	require.NoError(t, err)

	// The escalation-prone grantor: holds ONLY org:remote_applications:* (covers
	// the membership endpoint's org:remote_applications:update gate) but NOT org:*.
	require.NoError(t, coreSvc.DefineRole(ctx, org.Slug, "ra-manager"))
	require.NoError(t, coreSvc.SetRolePermissions(ctx, org.Slug, "ra-manager", []string{"org:remote_applications:*"}))
	require.NoError(t, coreSvc.AddMember(ctx, org.Slug, manager.ID))
	require.NoError(t, coreSvc.AssignRole(ctx, org.Slug, manager.ID, "ra-manager"))

	// A remote-app owned by the org, addressed by slug on the membership route.
	raSlug := prefix + "-app"
	_, err = coreSvc.UpsertRemoteApplication(ctx, core.RemoteApplication{
		Slug:    raSlug,
		OrgID:   org.ID,
		Issuer:  "https://" + prefix + "-app.example/issuer",
		JWKSURI: "https://example.com/jwks.json",
		Enabled: true,
	})
	require.NoError(t, err)

	managerTok := issueBoundaryUserToken(t, ctx, coreSvc, manager)
	ownerTok := issueBoundaryUserToken(t, ctx, coreSvc, owner)
	membershipPath := "/orgs/" + org.Slug + "/remote-applications/" + raSlug + "/memberships"
	post := func(token, role string) (int, string) {
		return remoteApplicationBoundaryRequestPath(t, server.URL, membershipPath, http.MethodPost, token,
			map[string]any{"org": org.Slug, "role": role})
	}

	// KEYSTONE: the ra-manager passes the endpoint gates (it holds
	// org:remote_applications:update) but assigning the `owner` role (org:*)
	// confers perms it lacks → 403 role_exceeds_grantor. This is the #94 fix.
	status, body := post(managerTok, "owner")
	require.Equal(t, http.StatusForbidden, status, body)
	require.Contains(t, body, "role_exceeds_grantor", "ra-manager must NOT be able to grant the owner role to a remote-app")

	// Control: the ra-manager CAN bind the remote-app to a role whose perms it
	// fully holds (a role granting only org:remote_applications:read).
	require.NoError(t, coreSvc.DefineRole(ctx, org.Slug, "ra-reader"))
	require.NoError(t, coreSvc.SetRolePermissions(ctx, org.Slug, "ra-reader", []string{"org:remote_applications:read"}))
	status, body = post(managerTok, "ra-reader")
	require.Equal(t, http.StatusOK, status, body)

	// The org owner (org:*) CAN assign the owner role — escalation rule does not
	// trip for an actor that holds everything.
	status, body = post(ownerTok, "owner")
	require.Equal(t, http.StatusOK, status, body)
}

// TestNoEscalationMemberRoleAssignHTTP covers grant path 2:
// POST /orgs/{org}/members/{user_id}/roles (handleOrgMemberRolesPOST).
//
// A grantor holding org:members:* (which covers the org:members:update gate) but
// NOT org:* cannot assign the `owner` role; an org owner can.
func TestNoEscalationMemberRoleAssignHTTP(t *testing.T) {
	ctx := context.Background()
	prefix := fmt.Sprintf("noesc-mr-%d", time.Now().UnixNano())
	coreSvc, server := newGrantPathTestServer(t, prefix, nil)

	owner := createBoundaryUser(t, ctx, coreSvc, prefix+"-owner")
	manager := createBoundaryUser(t, ctx, coreSvc, prefix+"-manager")
	target := createBoundaryUser(t, ctx, coreSvc, prefix+"-target")
	org, err := coreSvc.CreateOrgForUser(ctx, core.CreateOrgForUserRequest{Slug: prefix + "-org", OwnerUserID: owner.ID})
	require.NoError(t, err)

	// Grantor holds org:members:* (covers the org:members:update gate) but not org:*.
	require.NoError(t, coreSvc.DefineRole(ctx, org.Slug, "member-manager"))
	require.NoError(t, coreSvc.SetRolePermissions(ctx, org.Slug, "member-manager", []string{"org:members:*"}))
	require.NoError(t, coreSvc.AddMember(ctx, org.Slug, manager.ID))
	require.NoError(t, coreSvc.AssignRole(ctx, org.Slug, manager.ID, "member-manager"))
	require.NoError(t, coreSvc.AddMember(ctx, org.Slug, target.ID))

	managerTok := issueBoundaryUserToken(t, ctx, coreSvc, manager)
	ownerTok := issueBoundaryUserToken(t, ctx, coreSvc, owner)
	path := "/orgs/" + org.Slug + "/members/" + target.ID + "/roles"
	post := func(token, role string) (int, string) {
		return remoteApplicationBoundaryRequestPath(t, server.URL, path, http.MethodPost, token, map[string]any{"role": role})
	}

	// The member-manager cannot grant the owner role (org:*) it doesn't hold.
	status, body := post(managerTok, "owner")
	require.Equal(t, http.StatusForbidden, status, body)
	require.Contains(t, body, "role_exceeds_grantor")

	// Control: it CAN assign a role whose perms it fully holds.
	require.NoError(t, coreSvc.DefineRole(ctx, org.Slug, "member-reader"))
	require.NoError(t, coreSvc.SetRolePermissions(ctx, org.Slug, "member-reader", []string{"org:members:read"}))
	status, body = post(managerTok, "member-reader")
	require.Equal(t, http.StatusOK, status, body)

	// The owner (org:*) CAN assign the owner role.
	status, body = post(ownerTok, "owner")
	require.Equal(t, http.StatusOK, status, body)
}

// TestNoEscalationRolePermSetHTTP covers grant path 3:
// PUT /orgs/{org}/roles/{role} (handleOrgRolePUT).
//
// A grantor holding org:roles:* (covers the org:roles:update gate) plus jobs:read
// but NOT jobs:write cannot set a role's perms to include jobs:write; an owner can.
func TestNoEscalationRolePermSetHTTP(t *testing.T) {
	ctx := context.Background()
	prefix := fmt.Sprintf("noesc-rp-%d", time.Now().UnixNano())
	coreSvc, server := newGrantPathTestServer(t, prefix, []core.PermissionDef{
		{Name: "jobs:read"}, {Name: "jobs:write"},
	})

	manager := createBoundaryUser(t, ctx, coreSvc, prefix+"-manager")
	fullEditor := createBoundaryUser(t, ctx, coreSvc, prefix+"-full")
	// Org owner of record; the org needs an owner, but the no-escalation contrast
	// here is between two NON-owner editors so the single-role membership model
	// doesn't force us to demote the owner.
	owner := createBoundaryUser(t, ctx, coreSvc, prefix+"-owner")
	org, err := coreSvc.CreateOrgForUser(ctx, core.CreateOrgForUserRequest{Slug: prefix + "-org", OwnerUserID: owner.ID})
	require.NoError(t, err)

	// Limited grantor: can update roles + holds jobs:read, but NOT jobs:write.
	require.NoError(t, coreSvc.DefineRole(ctx, org.Slug, "role-editor"))
	require.NoError(t, coreSvc.SetRolePermissions(ctx, org.Slug, "role-editor", []string{"org:roles:*", "jobs:read"}))
	require.NoError(t, coreSvc.AddMember(ctx, org.Slug, manager.ID))
	require.NoError(t, coreSvc.AssignRole(ctx, org.Slug, manager.ID, "role-editor"))

	// Full grantor: can update roles + holds jobs:read AND jobs:write.
	require.NoError(t, coreSvc.DefineRole(ctx, org.Slug, "full-editor"))
	require.NoError(t, coreSvc.SetRolePermissions(ctx, org.Slug, "full-editor", []string{"org:roles:*", "jobs:read", "jobs:write"}))
	require.NoError(t, coreSvc.AddMember(ctx, org.Slug, fullEditor.ID))
	require.NoError(t, coreSvc.AssignRole(ctx, org.Slug, fullEditor.ID, "full-editor"))

	managerTok := issueBoundaryUserToken(t, ctx, coreSvc, manager)
	fullTok := issueBoundaryUserToken(t, ctx, coreSvc, fullEditor)
	put := func(token, role string, perms []string) (int, string) {
		return remoteApplicationBoundaryRequestPath(t, server.URL, "/orgs/"+org.Slug+"/roles/"+role, http.MethodPut, token,
			map[string]any{"permissions": perms})
	}

	// Cannot set a role to include jobs:write (a perm the editor lacks).
	status, body := put(managerTok, prefix+"-escalated", []string{"jobs:read", "jobs:write"})
	require.Equal(t, http.StatusForbidden, status, body)
	require.Contains(t, body, "permission_grant_denied")

	// Control: it CAN set a role to perms it fully holds.
	status, body = put(managerTok, prefix+"-readonly", []string{"jobs:read"})
	require.Equal(t, http.StatusOK, status, body)

	// The full editor holds jobs:write, so it CAN author a role with jobs:write.
	status, body = put(fullTok, prefix+"-full", []string{"jobs:read", "jobs:write"})
	require.Equal(t, http.StatusOK, status, body)
}

// TestNoEscalationPlatformRoleGrantHTTP covers grant path 6:
// POST /admin/platform-roles/{role}/grant (handlePlatformRoleGrantPOST).
//
// A limited platform-admin holding platform:members:create (so it passes the
// endpoint gate) but NOT platform:users:ban cannot assign a platform role that
// confers platform:users:ban; a super-admin (platform:*) can.
func TestNoEscalationPlatformRoleGrantHTTP(t *testing.T) {
	ctx := context.Background()
	prefix := fmt.Sprintf("noesc-pg-%d", time.Now().UnixNano())
	coreSvc, server := newGrantPathTestServer(t, prefix, nil)

	superU := createBoundaryUser(t, ctx, coreSvc, prefix+"-super")
	limitedU := createBoundaryUser(t, ctx, coreSvc, prefix+"-limited")
	targetU := createBoundaryUser(t, ctx, coreSvc, prefix+"-target")
	require.NoError(t, coreSvc.EnsurePlatformSuperAdmin(ctx, superU.ID))

	// Limited admin: can grant members + create roles, but does NOT hold
	// platform:users:ban.
	limitedRole := prefix + "-limited-role"
	require.NoError(t, coreSvc.DefinePlatformRole(ctx, limitedRole))
	require.NoError(t, coreSvc.SetPlatformRolePermissions(ctx, limitedRole, []string{
		core.PermPlatformMembersCreate, core.PermPlatformRolesCreate, core.PermPlatformRolesRead,
	}))
	require.NoError(t, coreSvc.AssignPlatformRole(ctx, limitedU.ID, limitedRole))

	// A platform role that confers platform:users:ban (out of the limited admin's set).
	powerRole := prefix + "-power-role"
	require.NoError(t, coreSvc.DefinePlatformRole(ctx, powerRole))
	require.NoError(t, coreSvc.SetPlatformRolePermissions(ctx, powerRole, []string{core.PermPlatformUsersBan}))

	// A platform role within the limited admin's set (only platform:roles:read).
	tameRole := prefix + "-tame-role"
	require.NoError(t, coreSvc.DefinePlatformRole(ctx, tameRole))
	require.NoError(t, coreSvc.SetPlatformRolePermissions(ctx, tameRole, []string{core.PermPlatformRolesRead}))

	superTok := issueBoundaryUserToken(t, ctx, coreSvc, superU)
	limitedTok := issueBoundaryUserToken(t, ctx, coreSvc, limitedU)
	grant := func(token, role string) (int, string) {
		return remoteApplicationBoundaryRequestPath(t, server.URL, "/admin/platform-roles/"+role+"/grant", http.MethodPost, token,
			map[string]any{"user_id": targetU.ID})
	}

	// The limited admin cannot grant a role conferring platform:users:ban → 403.
	status, body := grant(limitedTok, powerRole)
	require.Equal(t, http.StatusForbidden, status, body)
	require.Contains(t, body, "role_exceeds_grantor")

	// Control: it CAN grant a role whose perms it fully holds.
	status, body = grant(limitedTok, tameRole)
	require.Equal(t, http.StatusOK, status, body)

	// The super-admin (platform:*) CAN grant the power role.
	status, body = grant(superTok, powerRole)
	require.Equal(t, http.StatusOK, status, body)
}

// TestNoEscalationOrgInviteHTTP covers grant path 5 over HTTP:
// POST /orgs/{org}/invites (handleOrgInvitesPOST). The core invariant is already
// covered by core.TestOrgInviteNoEscalation; this asserts the HTTP wiring returns
// 403 role_exceeds_grantor for an inviter that holds a subset, 201 for an owner.
func TestNoEscalationOrgInviteHTTP(t *testing.T) {
	ctx := context.Background()
	prefix := fmt.Sprintf("noesc-inv-%d", time.Now().UnixNano())
	coreSvc, server := newGrantPathTestServer(t, prefix, nil)

	owner := createBoundaryUser(t, ctx, coreSvc, prefix+"-owner")
	inviter := createBoundaryUser(t, ctx, coreSvc, prefix+"-inviter")
	invitee := createBoundaryUser(t, ctx, coreSvc, prefix+"-invitee")
	org, err := coreSvc.CreateOrgForUser(ctx, core.CreateOrgForUserRequest{Slug: prefix + "-org", OwnerUserID: owner.ID})
	require.NoError(t, err)

	// Inviter can create members (passes the org:members:create gate) but is not owner.
	require.NoError(t, coreSvc.DefineRole(ctx, org.Slug, "inviter-role"))
	require.NoError(t, coreSvc.SetRolePermissions(ctx, org.Slug, "inviter-role", []string{"org:members:*"}))
	require.NoError(t, coreSvc.AddMember(ctx, org.Slug, inviter.ID))
	require.NoError(t, coreSvc.AssignRole(ctx, org.Slug, inviter.ID, "inviter-role"))

	inviterTok := issueBoundaryUserToken(t, ctx, coreSvc, inviter)
	ownerTok := issueBoundaryUserToken(t, ctx, coreSvc, owner)
	invite := func(token, role string) (int, string) {
		return remoteApplicationBoundaryRequestPath(t, server.URL, "/orgs/"+org.Slug+"/invites", http.MethodPost, token,
			map[string]any{"user_id": invitee.ID, "role": role})
	}

	// Inviting an `owner` (org:*) exceeds the inviter's authority → 403.
	status, body := invite(inviterTok, "owner")
	require.Equal(t, http.StatusForbidden, status, body)
	require.Contains(t, body, "role_exceeds_grantor")

	// The owner CAN invite to the owner role → 201.
	status, body = invite(ownerTok, "owner")
	require.Equal(t, http.StatusCreated, status, body)
}

// TestNoEscalationDelegatedTokenCannotGrantPlatformRole is the escalation-vector
// sweep guard for the delegated/federated-token path. A delegated access token
// presents an EMPTY local UserID (it has no `sub`; the principal is the issuer's
// delegated subject). The no-escalation check on the platform grant handlers
// resolves the actor's authority from claims.UserID — so a delegated actor's
// effective authority is computed for an EMPTY user. That FAILS CLOSED: the
// lookup hard-errors (an empty UUID can't index profiles.platform_user_roles),
// so the handler returns permission_validate_failed (500) rather than silently
// granting. Either branch — error or empty-set — bars escalation; this test
// locks the fail-closed property at the core boundary so a federated token can
// never be driven to grant a platform role it should not.
func TestNoEscalationDelegatedTokenCannotGrantPlatformRole(t *testing.T) {
	ctx := context.Background()
	prefix := fmt.Sprintf("noesc-deleg-%d", time.Now().UnixNano())
	coreSvc, _ := newGrantPathTestServer(t, prefix, nil)

	// A delegated actor presents an EMPTY local UserID. Validating a platform
	// grant for it must NEVER succeed-with-no-offending — it either fails closed
	// (error) or returns the requested perm as offending. It must not silently
	// allow the grant.
	_, offending, err := coreSvc.ValidatePlatformGrant(ctx, "", []string{core.PermPlatformUsersRead}, false)
	if err == nil {
		require.Contains(t, offending, core.PermPlatformUsersRead,
			"a delegated actor (empty UserID) must not be able to grant any platform permission")
	}

	// Same for the org grant validator: an empty actor must not be granted org
	// authority — it fails closed (error) or reports the perm as offending.
	org, err := coreSvc.CreateOrgForUser(ctx, core.CreateOrgForUserRequest{Slug: prefix + "-org", OwnerUserID: createBoundaryUser(t, ctx, coreSvc, prefix+"-owner").ID})
	require.NoError(t, err)
	_, orgOffending, oerr := coreSvc.ValidateGrant(ctx, org.Slug, "", []string{core.PermOrgMembersRead}, false)
	if oerr == nil {
		require.Contains(t, orgOffending, core.PermOrgMembersRead,
			"a delegated actor (empty UserID) must not be able to grant any org permission")
	}
}
