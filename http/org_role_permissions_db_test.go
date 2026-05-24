package authhttp

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// Org RBAC management endpoints (authkit #46), DB-backed (skips without
// AUTHKIT_TEST_DATABASE_URL). Reuses oatTestEnv from org_access_tokens_db_test.go.
func TestOrgRolePermissions_HTTP(t *testing.T) {
	env := newOATTestEnv(t)
	owner := env.addUser("rp-owner-" + env.slug)
	env.addMember(owner, "owner") // owner = `*`
	ownerJWT := env.jwtFor(owner)

	// rolemgr holds org:roles:manage + endpoint:deploy (but NOT endpoint:read).
	env.seedRole("rolemgr", "org:roles:manage", "endpoint:deploy")
	rolemgr := env.addUser("rp-rolemgr-" + env.slug)
	env.addMember(rolemgr, "rolemgr")

	rolePerms := func(role string) string { return "/orgs/" + env.slug + "/roles/" + role + "/permissions" }

	t.Run("catalog = base UNION app", func(t *testing.T) {
		w := env.do(http.MethodGet, "/permissions", ownerJWT, "")
		require.Equal(t, http.StatusOK, w.Code)
		var b struct {
			Permissions []struct{ Name string } `json:"permissions"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &b))
		got := map[string]bool{}
		for _, p := range b.Permissions {
			got[p.Name] = true
		}
		require.True(t, got["org:roles:manage"], "base perm present")
		require.True(t, got["endpoint:deploy"], "app perm present")
	})

	t.Run("owner sets a role's permissions, then reads them back", func(t *testing.T) {
		w := env.do(http.MethodPut, rolePerms("deployer"), ownerJWT, `{"permissions":["endpoint:deploy"]}`)
		require.Equal(t, http.StatusOK, w.Code)
		w = env.do(http.MethodGet, rolePerms("deployer"), ownerJWT, "")
		require.Equal(t, http.StatusOK, w.Code)
		require.Contains(t, w.Body.String(), "endpoint:deploy")
	})

	t.Run("unknown permission rejected", func(t *testing.T) {
		w := env.do(http.MethodPut, rolePerms("deployer"), ownerJWT, `{"permissions":["bogus:perm"]}`)
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "unknown_permission")
	})

	t.Run("caller without org:roles:manage cannot edit role permissions", func(t *testing.T) {
		// deployer role holds only endpoint:deploy, not org:roles:manage.
		dep := env.addUser("rp-dep-" + env.slug)
		env.addMember(dep, "deployer")
		w := env.do(http.MethodPut, rolePerms("deployer"), env.jwtFor(dep), `{"permissions":["endpoint:deploy"]}`)
		require.Equal(t, http.StatusForbidden, w.Code)
		require.JSONEq(t, `{"error":"forbidden"}`, w.Body.String())
	})

	t.Run("no-escalation: rolemgr cannot grant a permission it lacks", func(t *testing.T) {
		// rolemgr has org:roles:manage but only endpoint:deploy (not endpoint:read).
		w := env.do(http.MethodPut, rolePerms("deployer"), env.jwtFor(rolemgr), `{"permissions":["endpoint:read"]}`)
		require.Equal(t, http.StatusForbidden, w.Code)
		require.Contains(t, w.Body.String(), "permission_grant_denied")
		require.Contains(t, w.Body.String(), "endpoint:read")
	})

	t.Run("rolemgr CAN grant a permission it holds", func(t *testing.T) {
		w := env.do(http.MethodPut, rolePerms("deployer"), env.jwtFor(rolemgr), `{"permissions":["endpoint:deploy"]}`)
		require.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("member effective permissions (owner = all catalog via *)", func(t *testing.T) {
		w := env.do(http.MethodGet, "/orgs/"+env.slug+"/members/"+owner+"/permissions", ownerJWT, "")
		require.Equal(t, http.StatusOK, w.Code)
		require.Contains(t, w.Body.String(), "endpoint:deploy")
		require.Contains(t, w.Body.String(), "org:roles:manage")
	})
}
