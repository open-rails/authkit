package authhttp

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	core "github.com/open-rails/authkit/core"
	authcore "github.com/open-rails/authkit/internal/authcore"
	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/stretchr/testify/require"
)

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
	coreSvc := authcore.NewService(opts, ks, core.WithPostgres(pool))
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

func adminUsersStatus(t *testing.T, s *Service, token, rawQuery string) int {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/users?"+rawQuery, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	s.APIHandler().ServeHTTP(w, r)
	return w.Code
}

func adminUserPathStatus(t *testing.T, s *Service, token, path string) int {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	s.APIHandler().ServeHTTP(w, r)
	return w.Code
}

func adminIDsOf(users []core.AdminUser) []string {
	out := make([]string, len(users))
	for i := range users {
		out[i] = users[i].ID
	}
	return out
}

func TestAdminUsersListHTTP_GenericDirectory(t *testing.T) {
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

	// Root catalog role assignment for A + B.
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
		resp := adminListUsers(t, s, token, "search="+prefix+"&page_size=100&root_role="+roleSlug)
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

	t.Run("deleted users use status filter", func(t *testing.T) {
		require.NoError(t, s.svc.SoftDeleteUser(ctx, idC))
		resp := adminListUsers(t, s, token, "search="+prefix+"&page_size=100&status=deleted")
		require.EqualValues(t, 1, resp.Total)
		require.Equal(t, idC, resp.Data[0].ID)
		require.Equal(t, http.StatusNotFound, adminUserPathStatus(t, s, token, "/admin/users/deleted"))
	})
}

// TestAdminUsersListOptionsFromQuery covers the surviving generic query
// parser (no remote-application slug field). Pure parse,
// no DB.
func TestAdminUsersListOptionsFromQuery(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/admin/users?page=2&page_size=25&search=alice&root_role=moderator&status=banned&sort=email&order=asc&entitlement=premium", nil)
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

func TestAdminUsersRequiresRootPermissionAcrossPrincipalTypes(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	s := newAdminDirectoryService(t, pool)

	suffix := time.Now().UnixNano()
	prefix := fmt.Sprintf("hauth%d", suffix)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username LIKE $1`, prefix+"%")
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.api_keys WHERE name LIKE $1`, prefix+"%")
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug LIKE $1`, prefix+"%")
	})

	adminID := createAdminTestUser(t, s, ctx, prefix+"admin", true)
	plainID := createAdminTestUser(t, s, ctx, prefix+"plain", false)
	adminJWT, _, err := s.svc.IssueAccessToken(ctx, adminID, "", nil)
	require.NoError(t, err)
	plainJWT, _, err := s.svc.IssueAccessToken(ctx, plainID, "", nil)
	require.NoError(t, err)

	apiKeyAllow := mintAdminTestAPIKey(t, s, ctx, prefix+"api-allow", core.SuperAdminRoleName, adminID)
	apiKeyDeny := mintAdminTestAPIKey(t, s, ctx, prefix+"api-deny", core.MemberRoleName, adminID)
	delegatedAllow := mintAdminTestDelegatedToken(t, s, ctx, prefix+"delegated-allow", []string{core.PermRootUsersRead})
	delegatedDeny := mintAdminTestDelegatedToken(t, s, ctx, prefix+"delegated-deny", nil)
	remoteAllow := mintAdminTestRemoteAppToken(t, s, ctx, prefix+"remote-allow", core.OwnerRoleName)
	remoteDeny := mintAdminTestRemoteAppToken(t, s, ctx, prefix+"remote-deny", core.MemberRoleName)

	for name, token := range map[string]string{
		"user jwt":        adminJWT,
		"api key":         apiKeyAllow,
		"delegated token": delegatedAllow,
		"remote app":      remoteAllow,
	} {
		t.Run("allows "+name, func(t *testing.T) {
			require.Equal(t, http.StatusOK, adminUsersStatus(t, s, token, "search="+prefix))
		})
	}

	for name, token := range map[string]string{
		"user jwt":        plainJWT,
		"api key":         apiKeyDeny,
		"delegated token": delegatedDeny,
		"remote app":      remoteDeny,
	} {
		t.Run("denies "+name, func(t *testing.T) {
			require.Equal(t, http.StatusForbidden, adminUsersStatus(t, s, token, "search="+prefix))
		})
	}
}

func createAdminTestUser(t *testing.T, s *Service, ctx context.Context, username string, admin bool) string {
	t.Helper()
	u, err := s.svc.CreateUser(ctx, username+"@test.example", username)
	require.NoError(t, err)
	if admin {
		require.NoError(t, s.svc.AssignRoleBySlug(ctx, u.ID, "admin"))
	}
	return u.ID
}

func mintAdminTestAPIKey(t *testing.T, s *Service, ctx context.Context, name, role, createdBy string) string {
	t.Helper()
	_, token, err := s.svc.MintAPIKey(ctx, core.RootPersona, "", name, role, createdBy, nil)
	require.NoError(t, err)
	return token
}

func mintAdminTestDelegatedToken(t *testing.T, s *Service, ctx context.Context, slug string, perms []string) string {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, slug+"-kid")
	require.NoError(t, err)
	issuer := "https://" + slug + ".example"
	registerAdminTestRemoteApplication(t, s, ctx, slug, issuer, signer, "")
	require.NoError(t, s.verifier.AddIssuer(issuer, []string{"test-app"}, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
	}))
	token, err := core.MintDelegatedAccessToken(ctx, signer, core.DelegatedAccessParams{
		Issuer:           issuer,
		Audiences:        []string{"test-app"},
		DelegatedSubject: slug + "-subject",
		Permissions:      perms,
		TTL:              time.Minute,
	})
	require.NoError(t, err)
	return token
}

func mintAdminTestRemoteAppToken(t *testing.T, s *Service, ctx context.Context, slug, role string) string {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, slug+"-kid")
	require.NoError(t, err)
	issuer := "https://" + slug + ".example"
	ra := registerAdminTestRemoteApplication(t, s, ctx, slug, issuer, signer, role)
	require.NotEmpty(t, ra.ID)
	require.NoError(t, s.verifier.AddIssuer(issuer, []string{"test-app"}, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
	}))
	token, err := core.MintRemoteApplicationAccessToken(ctx, signer, core.RemoteApplicationAccessParams{
		Issuer:    issuer,
		Audiences: []string{"test-app"},
		TTL:       time.Minute,
	})
	require.NoError(t, err)
	return token
}

func registerAdminTestRemoteApplication(t *testing.T, s *Service, ctx context.Context, slug, issuer string, signer *jwtkit.RSASigner, role string) *core.RemoteApplication {
	t.Helper()
	gid, err := s.svc.EnsureRootGroup(ctx)
	require.NoError(t, err)
	ra, err := s.svc.UpsertRemoteApplication(ctx, core.RemoteApplication{
		Slug:              slug,
		PermissionGroupID: gid,
		Issuer:            issuer,
		Enabled:           true,
		PublicKeys: []core.RemoteAppKey{{
			KID:          signer.KID(),
			PublicKeyPEM: adminTestPublicKeyPEM(t, signer.PublicKey()),
		}},
	})
	require.NoError(t, err)
	if role != "" {
		require.NoError(t, s.svc.AddRemoteApplicationMember(ctx, ra.ID, role))
	}
	return ra
}

func adminTestPublicKeyPEM(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}
