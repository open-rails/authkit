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

// httpTestPG mirrors core.testPG: a pool against AUTHKIT_TEST_DATABASE_URL, or
// skip. The 001 schema must already be applied.
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
}

// newOATTestEnv wires a real multi-org Service (signer + verifier + pg) plus a
// mux mounting the OAT routes and a /whoami echo behind Required. authorizer may
// be nil (owner-only fallback minting).
func newOATTestEnv(t *testing.T, authorizer OATGrantAuthorizer) *oatTestEnv {
	t.Helper()
	pool := httpTestPG(t)
	ctx := context.Background()

	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)
	ks := core.Keyset{Active: signer, PublicKeys: map[string]*rsa.PublicKey{"kid": signer.PublicKey()}}
	opts := core.Options{
		Issuer:              "https://example.com",
		IssuedAudiences:     []string{"test-app"},
		ExpectedAudiences:   []string{"test-app"},
		AccessTokenDuration: time.Hour,
		OrgMode:             "multi",
		TokenPrefix:         "cozy",
	}
	coreSvc := core.NewService(opts, ks).WithPostgres(pool)
	ver := NewVerifier(WithSkew(5*time.Second), WithOrgMode("multi"), WithTokenPrefix("cozy"))
	require.NoError(t, ver.AddIssuer("https://example.com", []string{"test-app"}, IssuerOptions{RawKeys: coreSvc.PublicKeysByKID()}))
	ver.WithService(coreSvc)
	s := &Service{svc: coreSvc, verifier: ver}
	if authorizer != nil {
		s.WithOATGrantAuthorizer(authorizer)
	}

	required := Required(ver)
	mux := http.NewServeMux()
	mux.Handle("POST /orgs/{org}/access-tokens", required(http.HandlerFunc(s.handleOrgAccessTokensPOST)))
	mux.Handle("GET /orgs/{org}/access-tokens", required(http.HandlerFunc(s.handleOrgAccessTokensGET)))
	mux.Handle("DELETE /orgs/{org}/access-tokens/{token_id}", required(http.HandlerFunc(s.handleOrgAccessTokenDELETE)))
	mux.Handle("GET /whoami", required(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl, _ := ClaimsFromContext(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{
			"org": cl.Org, "permissions": cl.Permissions, "is_service": cl.IsService(), "user_id": cl.UserID,
		})
	})))

	slug := fmt.Sprintf("oat-http-%d", time.Now().UnixNano())
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
	var orgID string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO profiles.orgs (slug) VALUES ($1) RETURNING id::text`, slug).Scan(&orgID))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE id=$1::uuid`, orgID) })
	for _, role := range []string{"owner", "viewer"} {
		_, err := pool.Exec(ctx, `INSERT INTO profiles.org_roles (org_id, role) VALUES ($1::uuid, $2)`, orgID, role)
		require.NoError(t, err)
	}
	return &oatTestEnv{t: t, pool: pool, signer: signer, mux: mux, slug: slug}
}

func (e *oatTestEnv) addUser(username string) string {
	e.t.Helper()
	var id string
	require.NoError(e.t, e.pool.QueryRow(context.Background(),
		`INSERT INTO profiles.users (username) VALUES ($1) RETURNING id::text`, username).Scan(&id))
	e.t.Cleanup(func() { _, _ = e.pool.Exec(context.Background(), `DELETE FROM profiles.users WHERE id=$1::uuid`, id) })
	return id
}

func (e *oatTestEnv) addMember(orgSlug, userID string, roles ...string) {
	e.t.Helper()
	ctx := context.Background()
	var orgID string
	require.NoError(e.t, e.pool.QueryRow(ctx, `SELECT id::text FROM profiles.orgs WHERE slug=$1`, orgSlug).Scan(&orgID))
	_, err := e.pool.Exec(ctx, `INSERT INTO profiles.org_members (org_id, user_id) VALUES ($1::uuid, $2::uuid)`, orgID, userID)
	require.NoError(e.t, err)
	for _, r := range roles {
		_, err := e.pool.Exec(ctx, `INSERT INTO profiles.org_member_roles (org_id, user_id, role) VALUES ($1::uuid, $2::uuid, $3)`, orgID, userID, r)
		require.NoError(e.t, err)
	}
}

func (e *oatTestEnv) jwtFor(userID string, globalRoles ...string) string {
	claims := map[string]any{
		"iss": "https://example.com", "sub": userID, "aud": "test-app",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}
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

// TestOAT_HTTP_Lifecycle_Fallback exercises mint -> use -> list -> revoke ->
// rejected with NO grant authorizer installed (owner-only fallback; permissions
// are arbitrary opaque strings, not bounded by authkit).
func TestOAT_HTTP_Lifecycle_Fallback(t *testing.T) {
	env := newOATTestEnv(t, nil)
	slug := env.slug
	base := "/orgs/" + slug + "/access-tokens"

	owner := env.addUser("oat-owner-" + slug)
	env.addMember(slug, owner, "owner")
	member := env.addUser("oat-member-" + slug)
	env.addMember(slug, member, "viewer")
	ownerJWT := env.jwtFor(owner)
	memberJWT := env.jwtFor(member)

	t.Run("non-owner member cannot mint (fallback owner gate)", func(t *testing.T) {
		w := env.do(http.MethodPost, base, memberJWT, `{"name":"x","permissions":["endpoint:read"]}`)
		require.Equal(t, http.StatusForbidden, w.Code)
		require.JSONEq(t, `{"error":"forbidden"}`, w.Body.String())
	})

	var plaintext, tokenID string
	t.Run("owner mints with permissions (secret shown once)", func(t *testing.T) {
		w := env.do(http.MethodPost, base, ownerJWT, `{"name":"ci","permissions":["endpoint:deploy","repo:read"]}`)
		require.Equal(t, http.StatusCreated, w.Code)
		var body struct {
			ID          string   `json:"id"`
			Token       string   `json:"token"`
			Permissions []string `json:"permissions"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		require.Equal(t, []string{"endpoint:deploy", "repo:read"}, body.Permissions)
		require.Contains(t, body.Token, "cozy_oat_")
		plaintext, tokenID = body.Token, body.ID
	})

	t.Run("minted OAT authenticates as the org with its permissions", func(t *testing.T) {
		w := env.do(http.MethodGet, "/whoami", plaintext, "")
		require.Equal(t, http.StatusOK, w.Code)
		var who struct {
			Org         string   `json:"org"`
			Permissions []string `json:"permissions"`
			IsService   bool     `json:"is_service"`
			UserID      string   `json:"user_id"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &who))
		require.Equal(t, slug, who.Org)
		require.Equal(t, []string{"endpoint:deploy", "repo:read"}, who.Permissions)
		require.True(t, who.IsService)
		require.Empty(t, who.UserID)
	})

	t.Run("an OAT cannot mint another OAT", func(t *testing.T) {
		w := env.do(http.MethodPost, base, plaintext, `{"name":"nested","permissions":["endpoint:deploy"]}`)
		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.JSONEq(t, `{"error":"unauthorized"}`, w.Body.String())
	})

	t.Run("list shows the token, never the secret", func(t *testing.T) {
		w := env.do(http.MethodGet, base, ownerJWT, "")
		require.Equal(t, http.StatusOK, w.Code)
		require.Contains(t, w.Body.String(), tokenID)
		require.NotContains(t, w.Body.String(), plaintext)
	})

	t.Run("revoke, then the OAT is rejected; second revoke is 404", func(t *testing.T) {
		w := env.do(http.MethodDelete, base+"/"+tokenID, ownerJWT, "")
		require.Equal(t, http.StatusOK, w.Code)
		w = env.do(http.MethodGet, "/whoami", plaintext, "")
		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.JSONEq(t, `{"error":"token_revoked"}`, w.Body.String())
		w = env.do(http.MethodDelete, base+"/"+tokenID, ownerJWT, "")
		require.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("global admin (non-member) may mint in fallback", func(t *testing.T) {
		admin := env.addUser("oat-admin-" + slug)
		adminJWT := env.jwtFor(admin, "admin")
		w := env.do(http.MethodPost, base, adminJWT, `{"name":"ops","permissions":["endpoint:delete"]}`)
		require.Equal(t, http.StatusCreated, w.Code)
	})
}

// fakeGrantAuthorizer allows only permissions in `allow`; everything else is
// offending. It records the last caller seen for assertions.
type fakeGrantAuthorizer struct {
	allow      map[string]bool
	lastCaller OATGrantCaller
	lastOrg    string
}

func (f *fakeGrantAuthorizer) CanGrantOAT(ctx context.Context, caller OATGrantCaller, org string, permissions []string) (bool, []string, error) {
	f.lastCaller = caller
	f.lastOrg = org
	var offending []string
	for _, p := range permissions {
		if !f.allow[p] {
			offending = append(offending, p)
		}
	}
	return len(offending) == 0, offending, nil
}

// TestOAT_HTTP_MintHook verifies the OATGrantAuthorizer is consulted: it bounds
// which permissions may be granted, and a denial names the offending ones.
func TestOAT_HTTP_MintHook(t *testing.T) {
	auth := &fakeGrantAuthorizer{allow: map[string]bool{"endpoint:read": true, "endpoint:deploy": true}}
	env := newOATTestEnv(t, auth)
	slug := env.slug
	base := "/orgs/" + slug + "/access-tokens"

	// A user that is NOT an org owner — the hook, not membership, decides.
	user := env.addUser("oat-hookuser-" + slug)
	env.addMember(slug, user, "viewer")
	userJWT := env.jwtFor(user)

	t.Run("hook allows a permitted permission set", func(t *testing.T) {
		w := env.do(http.MethodPost, base, userJWT, `{"name":"ok","permissions":["endpoint:read","endpoint:deploy"]}`)
		require.Equal(t, http.StatusCreated, w.Code)
		require.Equal(t, user, auth.lastCaller.UserID)
		require.Equal(t, slug, auth.lastOrg)
	})

	t.Run("hook denies an over-broad request, naming offending permissions", func(t *testing.T) {
		w := env.do(http.MethodPost, base, userJWT, `{"name":"bad","permissions":["endpoint:read","endpoint:delete"]}`)
		require.Equal(t, http.StatusForbidden, w.Code)
		var body struct {
			Error     string   `json:"error"`
			Offending []string `json:"offending_permissions"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		require.Equal(t, "permission_grant_denied", body.Error)
		require.Equal(t, []string{"endpoint:delete"}, body.Offending)
	})

	t.Run("a service principal still cannot mint, even with a hook", func(t *testing.T) {
		// Mint a real OAT first (allowed), then try to use it to mint another.
		w := env.do(http.MethodPost, base, userJWT, `{"name":"seed","permissions":["endpoint:deploy"]}`)
		require.Equal(t, http.StatusCreated, w.Code)
		var body struct {
			Token string `json:"token"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		w = env.do(http.MethodPost, base, body.Token, `{"name":"nested","permissions":["endpoint:read"]}`)
		require.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
