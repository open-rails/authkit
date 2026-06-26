package authhttp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	authkit "github.com/open-rails/authkit"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/embedded"
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
	opts := embedded.Options{
		Issuer:                   "https://example.com",
		IssuedAudiences:          []string{"test-app"},
		ExpectedAudiences:        []string{"test-app"},
		AccessTokenDuration:      time.Hour,
		RegistrationVerification: embedded.RegistrationVerificationNone,
	}
	coreSvc, err := authcore.NewFromConfig(authcore.Config{
		Token: authcore.TokenConfig{
			Issuer:              opts.Issuer,
			IssuedAudiences:     opts.IssuedAudiences,
			ExpectedAudiences:   opts.ExpectedAudiences,
			AccessTokenDuration: opts.AccessTokenDuration,
		},
		Registration: authcore.RegistrationConfig{Verification: authcore.RegistrationVerificationNone},
		Keys: authcore.KeysConfig{Source: jwtkit.StaticKeySource{
			Active: signer,
			Pubs:   map[string]crypto.PublicKey{"admin-dir-kid": signer.PublicKey()},
		}},
		RBAC: authcore.RBACConfig{Groups: []authcore.PersonaDef{
			authcore.IntrinsicRootPersona(authcore.RoleDef{Name: "no-access"}),
		}},
	}, pool)
	require.NoError(t, err)
	// Seed the permission-group containment + root group so AssignGroupRole(root,...)
	// works (the directory tests grant the intrinsic root owner role). Mirrors the
	// other DB-backed http tests' setup.
	require.NoError(t, coreSvc.SeedPermissionGroupContainment(context.Background()))
	_, err = coreSvc.EnsureRootGroup(context.Background())
	require.NoError(t, err)
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

func adminIDsOf(users []authkit.AdminUser) []string {
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
	const roleSlug = embedded.OwnerRoleName // intrinsic root role.

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

	// Root owner assignment for A + B.
	require.NoError(t, s.svc.AssignGroupRole(ctx, embedded.RootPersona, "", idA, embedded.SubjectKindUser, roleSlug))
	require.NoError(t, s.svc.AssignGroupRole(ctx, embedded.RootPersona, "", idB, embedded.SubjectKindUser, roleSlug))

	// Ban D (so status filters can distinguish it).
	banUntil := time.Now().UTC().Add(time.Hour)
	require.NoError(t, s.svc.BanUser(ctx, idD, nil, &banUntil, idA))

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
	require.Equal(t, authkit.AdminUserStatusBanned, got.Status)
	require.Equal(t, authkit.AdminUserSortEmail, got.Sort)
	require.False(t, got.Desc) // order=asc
	require.Equal(t, "premium", got.Entitlement)
}

func TestAdminUserBanRoutesUseUserIDPath(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	s := newAdminDirectoryService(t, pool)

	suffix := time.Now().UnixNano()
	prefix := fmt.Sprintf("hban%d", suffix)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username LIKE $1`, prefix+"%")
	})

	adminID := createAdminTestUser(t, s, ctx, prefix+"admin", true)
	targetID := createAdminTestUser(t, s, ctx, prefix+"target", false)
	token, _, err := s.svc.IssueAccessToken(ctx, adminID, "", nil)
	require.NoError(t, err)

	post := func(path, body string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
		r.Header.Set("Authorization", "Bearer "+token)
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		s.APIHandler().ServeHTTP(w, r)
		return w
	}

	until := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	w := post("/admin/users/"+targetID+"/ban", `{"reason":"test ban","until":"`+until+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = post("/admin/users/"+targetID+"/ban", `{"reason":"missing until"}`)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	u, err := s.svc.AdminGetUser(ctx, targetID)
	require.NoError(t, err)
	require.NotNil(t, u.BannedAt)
	require.NotNil(t, u.BannedUntil)
	require.NotNil(t, u.BanReason)
	require.Equal(t, "test ban", *u.BanReason)

	w = post("/admin/users/"+targetID+"/unban", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	u, err = s.svc.AdminGetUser(ctx, targetID)
	require.NoError(t, err)
	require.Nil(t, u.BannedAt)
	require.Nil(t, u.BannedUntil)
	require.Nil(t, u.BanReason)

	w = post("/admin/users/"+targetID+"/ban", `{"reason":"infinite ban","until":"infinite"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	u, err = s.svc.AdminGetUser(ctx, targetID)
	require.NoError(t, err)
	require.NotNil(t, u.BannedAt)
	require.Nil(t, u.BannedUntil)

	w = post("/admin/users/ban", `{"user_id":"`+targetID+`"}`)
	require.NotEqual(t, http.StatusOK, w.Code, w.Body.String())
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

	apiKeyAllow := mintAdminTestAPIKey(t, s, ctx, prefix+"api-allow", embedded.OwnerRoleName, adminID)
	apiKeyDeny := mintAdminTestAPIKey(t, s, ctx, prefix+"api-deny", "no-access", adminID)
	delegatedAllow := mintAdminTestDelegatedToken(t, s, ctx, prefix+"delegated-allow", []string{embedded.PermRootResourcesRead})
	delegatedDeny := mintAdminTestDelegatedToken(t, s, ctx, prefix+"delegated-deny", nil)
	remoteAllow := mintAdminTestRemoteAppToken(t, s, ctx, prefix+"remote-allow", embedded.OwnerRoleName)
	remoteDeny := mintAdminTestRemoteAppToken(t, s, ctx, prefix+"remote-deny", "no-access")

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
		require.NoError(t, s.svc.AssignGroupRole(ctx, embedded.RootPersona, "", u.ID, embedded.SubjectKindUser, embedded.OwnerRoleName))
	}
	return u.ID
}

func mintAdminTestAPIKey(t *testing.T, s *Service, ctx context.Context, name, role, createdBy string) string {
	t.Helper()
	_, token, err := s.svc.MintAPIKey(ctx, embedded.RootPersona, "", name, role, createdBy, nil)
	require.NoError(t, err)
	return token
}

func mintAdminTestDelegatedToken(t *testing.T, s *Service, ctx context.Context, slug string, perms []string) string {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, slug+"-kid")
	require.NoError(t, err)
	issuer := "https://" + slug + ".example"
	// A delegated token's claimed permissions are bounded (#76) by the SIGNING
	// remote application's stored authority — the verifier rejects (401) any claim
	// outside that ceiling. Grant the app the root owner role when the token claims
	// permissions so the ceiling admits them; the deny case claims none and stays
	// authority-less (it 403s on the missing permission).
	raRole := ""
	if len(perms) > 0 {
		raRole = embedded.OwnerRoleName
	}
	registerAdminTestRemoteApplication(t, s, ctx, slug, issuer, signer, raRole)
	require.NoError(t, s.verifier.AddIssuer(issuer, []string{"test-app"}, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
	}))
	token, err := embedded.MintDelegatedAccessToken(ctx, signer, authkit.DelegatedAccessParams{
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
	token, err := embedded.MintRemoteApplicationAccessToken(ctx, signer, authkit.RemoteApplicationAccessParams{
		Issuer:    issuer,
		Audiences: []string{"test-app"},
		TTL:       time.Minute,
	})
	require.NoError(t, err)
	return token
}

func registerAdminTestRemoteApplication(t *testing.T, s *Service, ctx context.Context, slug, issuer string, signer *jwtkit.RSASigner, role string) *authkit.RemoteApplication {
	t.Helper()
	gid, err := s.svc.EnsureRootGroup(ctx)
	require.NoError(t, err)
	ra, err := s.svc.UpsertRemoteApplication(ctx, authkit.RemoteApplication{
		Slug:              slug,
		PermissionGroupID: gid,
		Issuer:            issuer,
		Enabled:           true,
		PublicKeys: []authkit.RemoteAppKey{{
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
