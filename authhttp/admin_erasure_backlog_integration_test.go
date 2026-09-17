package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// Two sites share one account store. The admin backlog route reports what each
// site still owes, over the real route, engine and Postgres.
func TestAdminErasureBacklogRoute(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	suffix := uniqueSuffix()
	issuerA := "https://backlog-a-" + suffix + ".test"
	issuerB := "https://backlog-b-" + suffix + ".test"

	cfg := newServerTestConfig()
	cfg.Token.Issuer = issuerA
	cfg.Token.AccountIssuers = []string{issuerB}
	cfg.RBAC = []embedded.PersonaDef{embedded.IntrinsicRootPersona(embedded.RoleDef{Name: "operator", Permissions: embedded.IntrinsicRootPermissions()})}
	srv, err := newServer(newServerClient(t, cfg, pool), WithoutRateLimiter())
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	require.NoError(t, srv.svc.SeedPermissionGroupContainment(ctx))
	_, err = srv.svc.EnsureRootGroup(ctx)
	require.NoError(t, err)

	call := func(bearer string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/admin/erasure/backlog", nil)
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		srv.apiHandler().ServeHTTP(w, r)
		return w
	}
	login := func(email, pass string) string {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/password/login", strings.NewReader(`{"identifier":"`+email+`","password":"`+pass+`"}`))
		r.Header.Set("Content-Type", "application/json")
		srv.apiHandler().ServeHTTP(w, r)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var out struct {
			AccessToken string `json:"access_token"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
		return out.AccessToken
	}
	backlog := func(bearer string) map[string]authkit.ErasureSiteBacklog {
		t.Helper()
		w := call(bearer)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var page authkit.ListPage[authkit.ErasureSiteBacklog]
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
		require.Equal(t, "list", page.Object)
		out := map[string]authkit.ErasureSiteBacklog{}
		for _, row := range page.Data {
			out[row.Site] = row
		}
		return out
	}

	operatorEmail, operatorPass := newCookieTestUser(t, pool, srv, "backlogop")
	operator, err := srv.svc.GetUserByEmail(ctx, operatorEmail)
	require.NoError(t, err)
	require.NoError(t, srv.svc.AssignGroupRoleGenesis(ctx, authkit.RootGroup(), authkit.UserSubject(operator.ID), "operator"))
	operatorToken := login(operatorEmail, operatorPass)

	victimEmail, _ := newCookieTestUser(t, pool, srv, "backlogvictim")
	victim, err := srv.svc.GetUserByEmail(ctx, victimEmail)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.account_erasure_obligations WHERE user_id=$1::uuid`, victim.ID)
	})

	require.Empty(t, backlog(operatorToken)[issuerA].Pending)
	require.NoError(t, srv.svc.SoftDeleteUser(ctx, victim.ID))

	rows := backlog(operatorToken)
	for _, issuer := range []string{issuerA, issuerB} {
		require.Equal(t, 1, rows[issuer].Pending, issuer)
		require.WithinDuration(t, time.Now(), rows[issuer].Oldest, time.Minute, issuer)
	}

	require.NoError(t, srv.svc.AcknowledgeErasure(ctx, issuerA, victim.ID))
	rows = backlog(operatorToken)
	require.Equal(t, 0, rows[issuerA].Pending, "acknowledged site drops out of the backlog")
	require.Equal(t, 1, rows[issuerB].Pending, "the offline site still owes the obligation")

	t.Run("unprivileged and anonymous callers are refused", func(t *testing.T) {
		require.Equal(t, http.StatusUnauthorized, call("").Code)
		plainEmail, plainPass := newCookieTestUser(t, pool, srv, "backlogplain")
		require.Equal(t, http.StatusForbidden, call(login(plainEmail, plainPass)).Code)
	})
}
