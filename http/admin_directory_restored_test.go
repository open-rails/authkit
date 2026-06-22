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

	"github.com/jackc/pgx/v5/pgxpool"
	core "github.com/open-rails/authkit/core"
	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/stretchr/testify/require"
)

// Restores coverage from the deleted admin_routes_test.go after the
// org→permission-group hard cut (#111). The old test asserted an OrgSlug field
// on AdminUserListOptions that no longer exists; the directory role filter now
// resolves through the root permission-group (group_role_assignments). This
// drives the real /admin/users HTTP listing against a live Postgres and asserts
// search / role filter / status / sort / pagination — the catalog role "admin"
// maps to the super-admin root role.

// newAdminDirectoryService builds a DB-backed http.Service with a verifier wired
// to its own signing keys, so a core-issued access token verifies through the
// /admin/users `required` gate.
func newAdminDirectoryService(t *testing.T, pool *pgxpool.Pool) *Service {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "admin-dir-kid")
	require.NoError(t, err)
	ks := core.Keyset{Active: signer, PublicKeys: map[string]crypto.PublicKey{"admin-dir-kid": signer.PublicKey()}}
	opts := core.Options{
		Issuer:                   "https://example.com",
		IssuedAudiences:          []string{"test-app"},
		ExpectedAudiences:        []string{"test-app"},
		AccessTokenDuration:      time.Hour,
		RegistrationVerification: core.RegistrationVerificationNone,
	}
	coreSvc := core.NewService(opts, ks, core.WithPostgres(pool))
	ver := NewVerifier(WithSkew(5 * time.Second))
	require.NoError(t, ver.AddIssuer(opts.Issuer, opts.ExpectedAudiences, IssuerOptions{
		RawKeys: coreSvc.PublicKeysByKID(),
		IsLocal: true,
	}))
	ver.WithService(coreSvc)
	return &Service{svc: coreSvc, verifier: ver}
}

// adminListUsers drives GET /admin/users with the given query string and the
// admin's bearer token, decoding the list envelope.
func adminListUsers(t *testing.T, s *Service, token, rawQuery string) adminUsersListResponse {
	t.Helper()
	h := s.APIHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/users?"+rawQuery, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp adminUsersListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return resp
}

func adminIDsOf(users []core.AdminUser) []string {
	out := make([]string, len(users))
	for i := range users {
		out[i] = users[i].ID
	}
	return out
}

func TestRestoredAdminUsersListHTTP_GenericDirectory(t *testing.T) {
	pool := newServerTestPool(t) // skips when AUTHKIT_TEST_DATABASE_URL unset
	ctx := context.Background()
	s := newAdminDirectoryService(t, pool)

	suffix := time.Now().UnixNano()
	prefix := fmt.Sprintf("hadir%d", suffix)
	const roleSlug = "admin" // catalog role; maps onto the super-admin root role.

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username LIKE $1`, prefix+"%")
	})

	mk := func(name string) string {
		u, err := s.svc.CreateUser(ctx, fmt.Sprintf("%s-%s@test.example", prefix, name), prefix+name)
		require.NoError(t, err, "create user %s", name)
		return u.ID
	}
	idA := mk("aaa")
	idB := mk("bbb")
	idC := mk("ccc")
	idD := mk("ddd")

	// Root catalog role assignment for A + B (group_role_assignments via the root group).
	require.NoError(t, s.svc.UpsertRoleBySlug(ctx, "Admin", roleSlug, nil))
	require.NoError(t, s.svc.AssignRoleBySlug(ctx, idA, roleSlug))
	require.NoError(t, s.svc.AssignRoleBySlug(ctx, idB, roleSlug))

	// Ban D (so status filters can distinguish it).
	require.NoError(t, s.svc.BanUser(ctx, idD, nil, nil, idA))

	// The admin caller is A (it carries the catalog admin role and is not banned).
	token, _, err := s.svc.IssueAccessToken(ctx, idA, "", nil)
	require.NoError(t, err)

	t.Run("search isolates this run", func(t *testing.T) {
		resp := adminListUsers(t, s, token, "search="+prefix+"&page_size=100")
		require.EqualValues(t, 4, resp.Total)
		require.Len(t, resp.Data, 4)
		require.Equal(t, "list", resp.Object)
	})

	t.Run("role filter resolves via root group", func(t *testing.T) {
		resp := adminListUsers(t, s, token, "search="+prefix+"&page_size=100&role="+roleSlug)
		require.EqualValues(t, 2, resp.Total)
		got := map[string]bool{}
		for _, u := range resp.Data {
			got[u.ID] = true
		}
		require.True(t, got[idA] && got[idB], "role filter must return the two assigned users")
	})

	t.Run("status filter banned vs active", func(t *testing.T) {
		banned := adminListUsers(t, s, token, "search="+prefix+"&page_size=100&status=banned")
		require.EqualValues(t, 1, banned.Total)
		require.Equal(t, idD, banned.Data[0].ID)

		active := adminListUsers(t, s, token, "search="+prefix+"&page_size=100&status=active")
		require.EqualValues(t, 3, active.Total)
	})

	t.Run("sort by username asc/desc", func(t *testing.T) {
		asc := adminListUsers(t, s, token, "search="+prefix+"&page_size=100&sort=username&order=asc")
		require.Equal(t, []string{idA, idB, idC, idD}, adminIDsOf(asc.Data))

		desc := adminListUsers(t, s, token, "search="+prefix+"&page_size=100&sort=username&order=desc")
		require.Equal(t, []string{idD, idC, idB, idA}, adminIDsOf(desc.Data))
	})

	t.Run("pagination", func(t *testing.T) {
		page2 := adminListUsers(t, s, token, "search="+prefix+"&sort=username&order=asc&page_size=2&page=2")
		require.EqualValues(t, 4, page2.Total)
		require.Equal(t, []string{idC, idD}, adminIDsOf(page2.Data))
		require.True(t, page2.HasMore == false)
	})
}

// TestRestoredAdminUsersListOptionsFromQuery covers the surviving generic query
// parser (no OrgSlug field — that was removed with the org plane). Pure parse,
// no DB.
func TestRestoredAdminUsersListOptionsFromQuery(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/admin/users?page=2&page_size=25&search=alice&role=moderator&status=banned&sort=email&order=asc&entitlement=premium", nil)
	got := adminUserListOptionsFromQuery(r)

	require.Equal(t, 2, got.Page)
	require.Equal(t, 25, got.PageSize)
	require.Equal(t, "alice", got.Search)
	require.Equal(t, "moderator", got.Role)
	require.Equal(t, core.AdminUserStatusBanned, got.Status)
	require.Equal(t, core.AdminUserSortEmail, got.Sort)
	require.False(t, got.Desc) // order=asc
	require.Equal(t, "premium", got.Entitlement)
}
