package authhttp

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// Introspection + REST-consolidation endpoints (authkit #46 follow-up),
// DB-backed (skips without AUTHKIT_TEST_DATABASE_URL). Reuses oatTestEnv.
func TestOrgRBACIntrospection_HTTP(t *testing.T) {
	env := newOATTestEnv(t)
	owner := env.addUser("intro-owner-" + env.slug)
	env.addMember(owner, "owner") // owner = `*`
	ownerJWT := env.jwtFor(owner)

	// A plain member with only the `deployer` role (endpoint:deploy, no org:read).
	dep := env.addUser("intro-dep-" + env.slug)
	env.addMember(dep, "deployer")
	depJWT := env.jwtFor(dep)

	org := "/orgs/" + env.slug

	t.Run("self GET /me returns roles + permissions without org:read", func(t *testing.T) {
		w := env.do(http.MethodGet, org+"/me", depJWT, "")
		require.Equal(t, http.StatusOK, w.Code)
		var b struct {
			Roles       []string
			Permissions []string
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &b))
		require.Equal(t, []string{"deployer"}, b.Roles)
		require.Equal(t, []string{"endpoint:deploy"}, b.Permissions)
	})

	t.Run("non-member /me is forbidden", func(t *testing.T) {
		stranger := env.addUser("intro-stranger-" + env.slug)
		w := env.do(http.MethodGet, org+"/me", env.jwtFor(stranger), "")
		require.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("permission check (self): granted subset only", func(t *testing.T) {
		w := env.do(http.MethodPost, org+"/permissions/check", depJWT, `{"permissions":["endpoint:deploy","endpoint:read","repo:read"]}`)
		require.Equal(t, http.StatusOK, w.Code)
		var b struct{ Granted []string }
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &b))
		require.Equal(t, []string{"endpoint:deploy"}, b.Granted)
	})

	t.Run("permission check for another member requires org:read", func(t *testing.T) {
		// dep lacks org:read, so it cannot check the owner.
		w := env.do(http.MethodPost, org+"/permissions/check", depJWT, `{"permissions":["endpoint:deploy"],"user_id":"`+owner+`"}`)
		require.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("owner can check another member (holds org:read via *)", func(t *testing.T) {
		w := env.do(http.MethodPost, org+"/permissions/check", ownerJWT, `{"permissions":["endpoint:deploy","endpoint:read"],"user_id":"`+dep+`"}`)
		require.Equal(t, http.StatusOK, w.Code)
		var b struct{ Granted []string }
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &b))
		require.Equal(t, []string{"endpoint:deploy"}, b.Granted) // dep has deploy, not read
	})

	t.Run("global admin self-check holds everything requested", func(t *testing.T) {
		ga := env.addUser("intro-ga-" + env.slug) // not even a member
		w := env.do(http.MethodPost, org+"/permissions/check", env.jwtFor(ga, "admin"), `{"permissions":["endpoint:deploy","repo:read"]}`)
		require.Equal(t, http.StatusOK, w.Code)
		var b struct{ Granted []string }
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &b))
		require.ElementsMatch(t, []string{"endpoint:deploy", "repo:read"}, b.Granted)
	})

	t.Run("single-role GET returns name + permissions", func(t *testing.T) {
		w := env.do(http.MethodGet, org+"/roles/deployer", ownerJWT, "")
		require.Equal(t, http.StatusOK, w.Code)
		var b struct {
			Role        string
			Permissions []string
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &b))
		require.Equal(t, "deployer", b.Role)
		require.Equal(t, []string{"endpoint:deploy"}, b.Permissions)
	})

	t.Run("single-role GET 404 for undefined role", func(t *testing.T) {
		w := env.do(http.MethodGet, org+"/roles/ghost", ownerJWT, "")
		require.Equal(t, http.StatusNotFound, w.Code)
		require.Contains(t, w.Body.String(), "role_not_found")
	})
}

// REST-consolidation: deletes now take a path param (hardcut, no body form).
func TestOrgRBACDeletes_PathParam(t *testing.T) {
	env := newOATTestEnv(t)
	owner := env.addUser("del-owner-" + env.slug)
	env.addMember(owner, "owner")
	ownerJWT := env.jwtFor(owner)
	org := "/orgs/" + env.slug

	t.Run("DELETE role by path param", func(t *testing.T) {
		env.seedRole("scratch", "endpoint:deploy")
		w := env.do(http.MethodDelete, org+"/roles/scratch", ownerJWT, "")
		require.Equal(t, http.StatusOK, w.Code)
		// gone: single-role GET now 404s.
		require.Equal(t, http.StatusNotFound, env.do(http.MethodGet, org+"/roles/scratch", ownerJWT, "").Code)
	})

	t.Run("DELETE protected owner role rejected", func(t *testing.T) {
		w := env.do(http.MethodDelete, org+"/roles/owner", ownerJWT, "")
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "protected_role")
	})

	t.Run("DELETE member by path param", func(t *testing.T) {
		victim := env.addUser("del-victim-" + env.slug)
		env.addMember(victim, "deployer")
		w := env.do(http.MethodDelete, org+"/members/"+victim, ownerJWT, "")
		require.Equal(t, http.StatusOK, w.Code)
		// gone: no longer listed among org members.
		lw := env.do(http.MethodGet, org+"/members", ownerJWT, "")
		require.Equal(t, http.StatusOK, lw.Code)
		require.NotContains(t, lw.Body.String(), victim)
	})
}
