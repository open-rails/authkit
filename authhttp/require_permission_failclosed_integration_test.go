package authhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

// #288/12: RequirePermission must deny when the checker cannot answer. The
// engine's Can hits Postgres; with the pool closed it returns an error and the
// gate must 403 without calling next (never 200, never 500).
func TestRequirePermission_FailsClosedWhenDatabaseIsDown(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := context.Background()
	svc, _ := newLivenessTestEngine(t, pg.Pool, "https://permfail.example.com")

	u, err := svc.CreateUser(ctx, uniqueEmail("permfail"), "permfail"+uniqueSuffix())
	require.NoError(t, err)
	require.NoError(t, svc.AssignGroupRoleGenesis(ctx, "root", "", u.ID, "user", "owner"))
	perms, err := svc.ListEffectivePermissions(ctx, u.ID, "user", "root", "")
	require.NoError(t, err)
	require.NotEmpty(t, perms, "fixture must grant a permission so the deny is not trivial")
	perm := perms[0]

	group, err := svc.GroupInstanceForSlug(ctx, "root", "")
	require.NoError(t, err)
	gate := verify.RequirePermission(svc, perm, func(*http.Request) verify.PermissionScope {
		return verify.PermissionScope{GroupID: group.ID, AuthorityIssuer: svc.Config().Token.Issuer, Persona: "root"}
	})
	serve := func() (int, bool) {
		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/gated", nil)
		gate(next).ServeHTTP(rec, req.WithContext(verify.SetClaims(req.Context(), verify.Claims{UserID: u.ID})))
		return rec.Code, called
	}

	code, called := serve()
	require.Equal(t, http.StatusOK, code)
	require.True(t, called, "with the database up the grant must admit")

	pg.Pool.Close()
	code, called = serve()
	require.Equal(t, http.StatusForbidden, code)
	require.False(t, called, "a checker error must never reach the handler")
}
