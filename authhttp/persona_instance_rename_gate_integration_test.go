package authhttp

import (
	"context"
	"net/http"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/stretchr/testify/require"
)

// #292: a slug RENAME is a claim and passes the same gate as creation —
// the persona's SlugPattern and reserved-slug escalation — so an owner
// cannot rename into a namespace they could not have created.
func TestInstanceRename_AppliesCreationSlugGate(t *testing.T) {
	srv, client := newInstanceCreateServer(t, WithoutRateLimiter())
	ctx := context.Background()
	_, ownerToken := newInstanceTestUser(t, srv, "orgrename")

	w := postOrg(srv, ownerToken, `{"slug":"rename-co"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	// SlugPattern forbids dots (the built-in rule alone would allow them).
	w = serveAuthJSON(srv, http.MethodPatch, "/org/rename-co", `{"slug":"rename.co"}`, ownerToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), string(authkit.CodeGroupSlugInvalid))

	// Reserved slug without the escalation role.
	w = serveAuthJSON(srv, http.MethodPatch, "/org/rename-co", `{"slug":"platform"}`, ownerToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), string(authkit.CodeGroupSlugReserved))
	require.Equal(t, http.StatusOK, serveAuthJSON(srv, http.MethodGet, "/org/rename-co", ``, ownerToken).Code, "refused rename must leave the slug in place")

	// A normal rename still works.
	w = serveAuthJSON(srv, http.MethodPatch, "/org/rename-co", `{"slug":"rename-inc"}`, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Holder of the escalation role may rename into the reserved slug.
	admin, adminToken := newInstanceTestUser(t, srv, "orgrenameadmin")
	require.NoError(t, client.Genesis().AssignRoleBySlug(ctx, admin, "site-admin"))
	w = postOrg(srv, adminToken, `{"slug":"admin-co"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	w = serveAuthJSON(srv, http.MethodPatch, "/org/admin-co", `{"slug":"platform"}`, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, http.StatusOK, serveAuthJSON(srv, http.MethodGet, "/org/platform", ``, adminToken).Code)
}
