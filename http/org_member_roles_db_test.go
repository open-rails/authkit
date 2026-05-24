package authhttp

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// Hardcut: member/role management is permission-gated (authkit #46). This covers
// the security-critical bits — org:members:manage gating + role-assignment
// no-escalation (a manager can't grant a role that exceeds their own perms, so
// only an owner-equivalent can grant the `owner` role).
func TestOrgMemberRoles_HardcutGatingAndNoEscalation(t *testing.T) {
	env := newOATTestEnv(t)
	owner := env.addUser("mr-owner-" + env.slug)
	env.addMember(owner, "owner")
	ownerJWT := env.jwtFor(owner)

	// memmgr can manage membership but only holds endpoint:deploy beyond that.
	env.seedRole("memmgr", "org:members:manage", "endpoint:deploy")
	memmgr := env.addUser("mr-memmgr-" + env.slug)
	env.addMember(memmgr, "memmgr")

	target := env.addUser("mr-target-" + env.slug)
	env.addMember(target, "deployer") // deployer = endpoint:deploy
	rolesPath := "/orgs/" + env.slug + "/members/" + target + "/roles"

	t.Run("non-manager cannot assign roles", func(t *testing.T) {
		// `target` (deployer) lacks org:members:manage.
		w := env.do(http.MethodPost, rolesPath, env.jwtFor(target), `{"role":"deployer"}`)
		require.Equal(t, http.StatusForbidden, w.Code)
		require.JSONEq(t, `{"error":"forbidden"}`, w.Body.String())
	})

	t.Run("manager assigns a role within its own permissions", func(t *testing.T) {
		w := env.do(http.MethodPost, rolesPath, env.jwtFor(memmgr), `{"role":"deployer"}`)
		require.Equal(t, http.StatusOK, w.Code) // memmgr holds endpoint:deploy
	})

	t.Run("no-escalation: manager cannot grant the owner role (= *)", func(t *testing.T) {
		w := env.do(http.MethodPost, rolesPath, env.jwtFor(memmgr), `{"role":"owner"}`)
		require.Equal(t, http.StatusForbidden, w.Code)
		require.Contains(t, w.Body.String(), "role_exceeds_grantor")
	})

	t.Run("owner (holds *) can grant the owner role", func(t *testing.T) {
		w := env.do(http.MethodPost, rolesPath, ownerJWT, `{"role":"owner"}`)
		require.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("manager can add a member", func(t *testing.T) {
		newbie := env.addUser("mr-newbie-" + env.slug)
		w := env.do(http.MethodPost, "/orgs/"+env.slug+"/members", env.jwtFor(memmgr), `{"user_id":"`+newbie+`"}`)
		require.Equal(t, http.StatusOK, w.Code)
	})
}
