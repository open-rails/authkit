package authhttp

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	core "github.com/open-rails/authkit/core"
	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/stretchr/testify/require"
)

func httpTestPG(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AUTHKIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTHKIT_TEST_DATABASE_URL not set; skipping DB-backed test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

type oatTestEnv struct {
	t      *testing.T
	pool   *pgxpool.Pool
	signer *jwtkit.RSASigner
	mux    *http.ServeMux
	slug   string
	orgID  string
}

// newOATTestEnv wires a multi-org Service with an app permission catalog, then
// seeds an org with roles + role->permissions (owner=`*`). OAT minting is now
// validated entirely inside authkit against the catalog + the caller's
// effective permissions (no host hook).
func newOATTestEnv(t *testing.T) *oatTestEnv {
	t.Helper()
	pool := httpTestPG(t)
	ctx := context.Background()

	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)
	ks := core.Keyset{Active: signer, PublicKeys: map[string]*rsa.PublicKey{"kid": signer.PublicKey()}}
	opts := core.Options{
		Issuer: "https://example.com", IssuedAudiences: []string{"test-app"},
		ExpectedAudiences: []string{"test-app"}, AccessTokenDuration: time.Hour,
		OrgMode: "multi", TokenPrefix: "cozy",
		PermissionCatalog: []core.PermissionDef{{Name: "endpoint:deploy"}, {Name: "endpoint:read"}, {Name: "repo:read"}},
	}
	coreSvc := core.NewService(opts, ks).WithPostgres(pool)
	ver := NewVerifier(WithSkew(5*time.Second), WithOrgMode("multi"), WithTokenPrefix("cozy"))
	require.NoError(t, ver.AddIssuer("https://example.com", []string{"test-app"}, IssuerOptions{RawKeys: coreSvc.PublicKeysByKID()}))
	ver.WithService(coreSvc)
	s := &Service{svc: coreSvc, verifier: ver}

	required := Required(ver)
	mux := http.NewServeMux()
	mux.Handle("POST /orgs/{org}/access-tokens", required(http.HandlerFunc(s.handleOrgAccessTokensPOST)))
	mux.Handle("GET /orgs/{org}/access-tokens", required(http.HandlerFunc(s.handleOrgAccessTokensGET)))
	mux.Handle("DELETE /orgs/{org}/access-tokens/{token_id}", required(http.HandlerFunc(s.handleOrgAccessTokenDELETE)))
	mux.Handle("GET /permissions", required(http.HandlerFunc(s.handlePermissionCatalogGET)))
	mux.Handle("GET /orgs/{org}/roles/{role}/permissions", required(http.HandlerFunc(s.handleOrgRolePermissionsGET)))
	mux.Handle("PUT /orgs/{org}/roles/{role}/permissions", required(http.HandlerFunc(s.handleOrgRolePermissionsPUT)))
	mux.Handle("GET /orgs/{org}/members/{user_id}/permissions", required(http.HandlerFunc(s.handleOrgMemberPermissionsGET)))
	mux.Handle("POST /orgs/{org}/members/{user_id}/roles", required(http.HandlerFunc(s.handleOrgMemberRolesPOST)))
	mux.Handle("POST /orgs/{org}/members", required(http.HandlerFunc(s.handleOrgMembersPOST)))
	mux.Handle("GET /whoami", required(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl, _ := ClaimsFromContext(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{"org": cl.Org, "permissions": cl.Permissions, "is_service": cl.IsService(), "user_id": cl.UserID})
	})))

	slug := fmt.Sprintf("oat-http-%d", time.Now().UnixNano())
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
	var orgID string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO profiles.orgs (slug) VALUES ($1) RETURNING id::text`, slug).Scan(&orgID))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE id=$1::uuid`, orgID) })
	env := &oatTestEnv{t: t, pool: pool, signer: signer, mux: mux, slug: slug, orgID: orgID}
	// Roles + their permissions. owner=`*`; tokenmgr can mint endpoint:deploy.
	env.seedRole("owner", "*")
	env.seedRole("deployer", "endpoint:deploy")
	env.seedRole("tokenmgr", "org:tokens:manage", "endpoint:deploy")
	return env
}

func (e *oatTestEnv) seedRole(role string, perms ...string) {
	e.t.Helper()
	ctx := context.Background()
	_, err := e.pool.Exec(ctx, `INSERT INTO profiles.org_roles (org_id, role) VALUES ($1::uuid,$2) ON CONFLICT DO NOTHING`, e.orgID, role)
	require.NoError(e.t, err)
	for _, p := range perms {
		_, err := e.pool.Exec(ctx, `INSERT INTO profiles.org_role_permissions (org_id, role, permission) VALUES ($1::uuid,$2,$3) ON CONFLICT DO NOTHING`, e.orgID, role, p)
		require.NoError(e.t, err)
	}
}

func (e *oatTestEnv) addUser(username string) string {
	e.t.Helper()
	var id string
	require.NoError(e.t, e.pool.QueryRow(context.Background(), `INSERT INTO profiles.users (username) VALUES ($1) RETURNING id::text`, username).Scan(&id))
	e.t.Cleanup(func() { _, _ = e.pool.Exec(context.Background(), `DELETE FROM profiles.users WHERE id=$1::uuid`, id) })
	return id
}

func (e *oatTestEnv) addMember(userID string, roles ...string) {
	e.t.Helper()
	ctx := context.Background()
	_, err := e.pool.Exec(ctx, `INSERT INTO profiles.org_members (org_id, user_id) VALUES ($1::uuid, $2::uuid)`, e.orgID, userID)
	require.NoError(e.t, err)
	for _, r := range roles {
		_, err := e.pool.Exec(ctx, `INSERT INTO profiles.org_member_roles (org_id, user_id, role) VALUES ($1::uuid,$2::uuid,$3)`, e.orgID, userID, r)
		require.NoError(e.t, err)
	}
}

func (e *oatTestEnv) jwtFor(userID string, globalRoles ...string) string {
	claims := map[string]any{"iss": "https://example.com", "sub": userID, "aud": "test-app", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	if len(globalRoles) > 0 {
		claims["global_roles"] = globalRoles
	}
	return signToken(e.t, e.signer, claims)
}

func (e *oatTestEnv) do(method, path, bearer, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	e.mux.ServeHTTP(w, r)
	return w
}

func TestOAT_HTTP_Lifecycle(t *testing.T) {
	env := newOATTestEnv(t)
	base := "/orgs/" + env.slug + "/access-tokens"
	owner := env.addUser("oat-owner-" + env.slug)
	env.addMember(owner, "owner")
	ownerJWT := env.jwtFor(owner)

	var plaintext, tokenID string
	t.Run("owner mints (owner holds * so any catalog perm)", func(t *testing.T) {
		w := env.do(http.MethodPost, base, ownerJWT, `{"name":"ci","permissions":["endpoint:deploy","endpoint:read"]}`)
		require.Equal(t, http.StatusCreated, w.Code)
		var b struct {
			ID, Token   string
			Permissions []string
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &b))
		require.Equal(t, []string{"endpoint:deploy", "endpoint:read"}, b.Permissions)
		require.Contains(t, b.Token, "cozy_oat_")
		plaintext, tokenID = b.Token, b.ID
	})
	t.Run("OAT authenticates as org with its permissions", func(t *testing.T) {
		w := env.do(http.MethodGet, "/whoami", plaintext, "")
		require.Equal(t, http.StatusOK, w.Code)
		var who struct {
			Org         string
			Permissions []string
			IsService   bool   `json:"is_service"`
			UserID      string `json:"user_id"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &who))
		require.Equal(t, env.slug, who.Org)
		require.Equal(t, []string{"endpoint:deploy", "endpoint:read"}, who.Permissions)
		require.True(t, who.IsService)
		require.Empty(t, who.UserID)
	})
	t.Run("OAT cannot mint another OAT", func(t *testing.T) {
		w := env.do(http.MethodPost, base, plaintext, `{"name":"x","permissions":["endpoint:deploy"]}`)
		require.Equal(t, http.StatusUnauthorized, w.Code)
	})
	t.Run("revoke -> rejected -> 404", func(t *testing.T) {
		require.Equal(t, http.StatusOK, env.do(http.MethodDelete, base+"/"+tokenID, ownerJWT, "").Code)
		w := env.do(http.MethodGet, "/whoami", plaintext, "")
		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.JSONEq(t, `{"error":"token_revoked"}`, w.Body.String())
		require.Equal(t, http.StatusNotFound, env.do(http.MethodDelete, base+"/"+tokenID, ownerJWT, "").Code)
	})
}

func TestOAT_HTTP_MintAuthorization(t *testing.T) {
	env := newOATTestEnv(t)
	base := "/orgs/" + env.slug + "/access-tokens"
	deployer := env.addUser("oat-deployer-" + env.slug)
	env.addMember(deployer, "deployer") // has endpoint:deploy but NOT org:tokens:manage
	tokenmgr := env.addUser("oat-tokenmgr-" + env.slug)
	env.addMember(tokenmgr, "tokenmgr") // org:tokens:manage + endpoint:deploy

	t.Run("caller without org:tokens:manage cannot mint", func(t *testing.T) {
		w := env.do(http.MethodPost, base, env.jwtFor(deployer), `{"name":"x","permissions":["endpoint:deploy"]}`)
		require.Equal(t, http.StatusForbidden, w.Code)
		require.JSONEq(t, `{"error":"forbidden"}`, w.Body.String())
	})
	t.Run("tokenmgr mints a permission it holds", func(t *testing.T) {
		require.Equal(t, http.StatusCreated, env.do(http.MethodPost, base, env.jwtFor(tokenmgr), `{"name":"ok","permissions":["endpoint:deploy"]}`).Code)
	})
	t.Run("tokenmgr cannot grant a permission it lacks (no-escalation)", func(t *testing.T) {
		w := env.do(http.MethodPost, base, env.jwtFor(tokenmgr), `{"name":"x","permissions":["endpoint:read"]}`)
		require.Equal(t, http.StatusForbidden, w.Code)
		require.Contains(t, w.Body.String(), "permission_grant_denied")
		require.Contains(t, w.Body.String(), "endpoint:read")
	})
	t.Run("unknown permission rejected", func(t *testing.T) {
		w := env.do(http.MethodPost, base, env.jwtFor(tokenmgr), `{"name":"x","permissions":["bogus:perm"]}`)
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "unknown_permission")
	})
	t.Run("reserved org:* perm not grantable to an OAT", func(t *testing.T) {
		w := env.do(http.MethodPost, base, env.jwtFor(tokenmgr), `{"name":"x","permissions":["org:roles:manage"]}`)
		require.Equal(t, http.StatusForbidden, w.Code)
		require.Contains(t, w.Body.String(), "permission_not_grantable_to_oat")
	})
	t.Run("wildcard not grantable to an OAT", func(t *testing.T) {
		w := env.do(http.MethodPost, base, env.jwtFor(tokenmgr), `{"name":"x","permissions":["*"]}`)
		require.Equal(t, http.StatusForbidden, w.Code)
		require.Contains(t, w.Body.String(), "permission_not_grantable_to_oat")
	})
	t.Run("global admin may mint any catalog permission", func(t *testing.T) {
		admin := env.addUser("oat-gadmin-" + env.slug)
		require.Equal(t, http.StatusCreated, env.do(http.MethodPost, base, env.jwtFor(admin, "admin"), `{"name":"ops","permissions":["endpoint:deploy","endpoint:read","repo:read"]}`).Code)
	})
}
