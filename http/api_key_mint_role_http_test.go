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

// TestAPIKeyMintRoleAuthorizationHTTP exercises the #95 role-based API-key mint
// contract over HTTP:
//   - the body field is `role` (a single org role slug), not `permissions`
//   - the key's effective permissions are RESOLVED from the role
//   - minting a role the minter does not fully hold is 403 (no-escalation)
//   - a role conferring reserved WRITE / wildcard perms is barred from a key
//   - resource-scope is orthogonal to the role
//
// Skips without AUTHKIT_TEST_DATABASE_URL.
func TestAPIKeyMintRoleAuthorizationHTTP(t *testing.T) {
	pool := remoteApplicationBoundaryPG(t)
	ctx := context.Background()
	prefix := fmt.Sprintf("apikey-role-%d", time.Now().UnixNano())

	signer, err := jwtkit.NewRSASigner(2048, "apikey-role")
	require.NoError(t, err)
	coreSvc := core.NewService(core.Options{
		Issuer:                   "https://" + prefix + ".authkit.test",
		IssuedAudiences:          []string{"plat"},
		ExpectedAudiences:        []string{"plat"},
		AccessTokenDuration:      time.Hour,
		RegistrationVerification: core.RegistrationVerificationNone,
		APIKeyPrefix:             "authkit",
		Permissions: []core.PermissionDef{
			{Name: "jobs:read"}, {Name: "jobs:write"},
		},
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
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.orgs WHERE slug LIKE $1`, prefix+"%")
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.users WHERE username LIKE $1`, prefix+"%")
	})

	owner := createBoundaryUser(t, ctx, coreSvc, prefix+"-owner")
	org, err := coreSvc.CreateOrgForUser(ctx, core.CreateOrgForUserRequest{Slug: prefix + "-org", OwnerUserID: owner.ID})
	require.NoError(t, err)
	base := "/orgs/" + org.Slug + "/api-keys"
	post := func(token string, body any) (int, string) {
		return remoteApplicationBoundaryRequestPath(t, server.URL, base, http.MethodPost, token, body)
	}

	// Roles the key can be bound to.
	require.NoError(t, coreSvc.DefineRole(ctx, org.Slug, "reader"))
	require.NoError(t, coreSvc.SetRolePermissions(ctx, org.Slug, "reader", []string{"jobs:read"}))
	require.NoError(t, coreSvc.DefineRole(ctx, org.Slug, "writer"))
	require.NoError(t, coreSvc.SetRolePermissions(ctx, org.Slug, "writer", []string{"jobs:read", "jobs:write"}))
	require.NoError(t, coreSvc.DefineRole(ctx, org.Slug, "wildcard"))
	require.NoError(t, coreSvc.SetRolePermissions(ctx, org.Slug, "wildcard", []string{"org:*"}))
	require.NoError(t, coreSvc.DefineRole(ctx, org.Slug, "audit"))
	require.NoError(t, coreSvc.SetRolePermissions(ctx, org.Slug, "audit", []string{core.PermOrgMembersRead}))

	// A FULL minter: can mint (org:api_keys:create) + holds every host perm + the
	// read-only reserved perm, so it may bind a key to any of the roles above (the
	// owner role only expands to org:*, which does NOT cover host perms like jobs:*).
	superMinter := createBoundaryUser(t, ctx, coreSvc, prefix+"-super")
	require.NoError(t, coreSvc.DefineRole(ctx, org.Slug, "super-minter"))
	require.NoError(t, coreSvc.SetRolePermissions(ctx, org.Slug, "super-minter", []string{
		core.PermOrgAPIKeysCreate, core.PermOrgMembersRead, "jobs:read", "jobs:write",
	}))
	require.NoError(t, coreSvc.AddMember(ctx, org.Slug, superMinter.ID))
	require.NoError(t, coreSvc.AssignRole(ctx, org.Slug, superMinter.ID, "super-minter"))
	superTok := issueBoundaryUserToken(t, ctx, coreSvc, superMinter)
	// The owner can still mint (holds org:api_keys:create via org:*) but only roles
	// whose perms it covers; used below for the wildcard-bar + unknown-role checks.
	ownerTok := issueBoundaryUserToken(t, ctx, coreSvc, owner)

	// A limited member: holds org:api_keys:create (can mint) + jobs:read, but NOT
	// jobs:write — so it may bind a key to `reader` but NOT to `writer`.
	limited := createBoundaryUser(t, ctx, coreSvc, prefix+"-limited")
	require.NoError(t, coreSvc.DefineRole(ctx, org.Slug, "minter"))
	require.NoError(t, coreSvc.SetRolePermissions(ctx, org.Slug, "minter", []string{core.PermOrgAPIKeysCreate, "jobs:read"}))
	require.NoError(t, coreSvc.AddMember(ctx, org.Slug, limited.ID))
	require.NoError(t, coreSvc.AssignRole(ctx, org.Slug, limited.ID, "minter"))
	limitedTok := issueBoundaryUserToken(t, ctx, coreSvc, limited)

	// 1. The mint body field is `role`; perms RESOLVE from the role.
	status, body := post(superTok, map[string]any{
		"name":      "ci",
		"role":      "writer",
		"resources": []map[string]string{{"kind": "repo", "id": "alpha"}},
	})
	require.Equal(t, http.StatusCreated, status, body)
	var mint map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &mint))
	require.Equal(t, "writer", mint["role"])
	perms, _ := mint["permissions"].([]any)
	require.ElementsMatch(t, []any{"jobs:read", "jobs:write"}, perms)
	// Resource-scope is orthogonal to the role.
	res, _ := mint["resources"].([]any)
	require.Len(t, res, 1)

	// 2. NO-ESCALATION: the limited minter holds jobs:read but not jobs:write, so
	//    binding a key to `writer` (which confers jobs:write) is 403.
	status, body = post(limitedTok, map[string]any{"name": "x", "role": "writer"})
	require.Equal(t, http.StatusForbidden, status, body)
	require.Contains(t, body, "permission_grant_denied")

	// ...but binding to `reader` (perms the minter fully holds) succeeds.
	status, body = post(limitedTok, map[string]any{"name": "ok", "role": "reader"})
	require.Equal(t, http.StatusCreated, status, body)

	// 3. A role conferring reserved WRITE / wildcard perms is barred from a key.
	status, body = post(ownerTok, map[string]any{"name": "x", "role": "wildcard"})
	require.Equal(t, http.StatusForbidden, status, body)
	require.Contains(t, body, "role_not_grantable_to_api_key")

	// 4. A role conferring only read-only reserved perms IS grantable.
	status, body = post(ownerTok, map[string]any{"name": "audit-bot", "role": "audit"})
	require.Equal(t, http.StatusCreated, status, body)
	require.Contains(t, body, core.PermOrgMembersRead)

	// 5. An unknown role is a 400.
	status, body = post(ownerTok, map[string]any{"name": "x", "role": "ghost"})
	require.Equal(t, http.StatusBadRequest, status, body)
	require.Contains(t, body, "unknown_role")

	// 6. A missing role is a 400.
	status, body = post(ownerTok, map[string]any{"name": "x"})
	require.Equal(t, http.StatusBadRequest, status, body)
	require.Contains(t, body, "missing_role")
}
