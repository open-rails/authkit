package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	core "github.com/open-rails/authkit/core"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/stretchr/testify/require"
)

// credTestConfig enables the credential/invite management capabilities under
// test: a "merchant" persona with api-key minting, remote-app registration, and
// invitations, plus a role catalog the keys/invites can reference. Passed via
// RBAC.Groups so authcore.NewFromConfig builds + installs the schema.
func credTestConfig() core.Config {
	return core.Config{
		Token: core.TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"a"}, ExpectedAudiences: []string{"a"}},
		RBAC: core.RBACConfig{Groups: []core.PersonaDef{{
			Name: "merchant", AllowedParents: []string{core.RootPersona},
			Routes: core.ManagementProfile{MemberAssignment: true, APIKeyMinting: true, RemoteAppRegistration: true, Invitation: true},
			Roles:  []core.RoleDef{{Name: "member", Permissions: []string{"merchant:catalog:read"}}},
		}}},
	}
}

// newCredTestService builds an http.Service over a REAL pool with the credential
// schema, seeds containment + root group, and stubs the authorizer to allow (the
// gate is covered by the no-DB route tests; here we exercise the DB-backed ops).
// Returns the service, the pool, and a freshly-created user id to act as caller.
func newCredTestService(t *testing.T) (*Service, *pgxpool.Pool, string) {
	t.Helper()
	dsn := os.Getenv("AUTHKIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTHKIT_TEST_DATABASE_URL not set; skipping DB-backed test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	ctx := context.Background()

	coreSvc, err := authcore.NewFromConfig(credTestConfig(), pool)
	require.NoError(t, err)
	require.NoError(t, coreSvc.SeedPermissionGroupContainment(ctx))
	_, err = coreSvc.EnsureRootGroup(ctx)
	require.NoError(t, err)

	var caller string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(&caller))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id = $1::uuid`, caller) })

	s := &Service{svc: coreSvc}
	s.groupCanFn = func(_ *http.Request, _, _, _, _ string) (bool, error) { return true, nil }
	return s, pool, caller
}

// drive runs one generated route handler at a concrete (no sub-resource) path,
// with the caller's claims set, and returns the recorder. Sub-resource DELETEs
// (:key / :app / :invite) are driven inline via driveSub.
func (s *Service) drive(t *testing.T, gr core.GeneratedRoute, instanceSlug, caller, body string) *httptest.ResponseRecorder {
	t.Helper()
	path := strings.ReplaceAll(gr.Path, ":instance_slug", instanceSlug)
	r := httptest.NewRequest(gr.Method, "http://x"+path, strings.NewReader(body))
	r = withMuxParams(r, gr.Path, nil)
	r = r.WithContext(setClaims(r.Context(), Claims{UserID: caller}))
	w := httptest.NewRecorder()
	s.generatedGroupHandler(gr).ServeHTTP(w, r)
	return w
}

// driveSub runs a sub-resource handler (DELETE with :key/:app/:invite) at a
// concrete path, with claims set.
func (s *Service) driveSub(t *testing.T, gr core.GeneratedRoute, repl *strings.Replacer, caller string) *httptest.ResponseRecorder {
	t.Helper()
	path := repl.Replace(gr.Path)
	r := httptest.NewRequest(gr.Method, "http://x"+path, nil)
	r = withMuxParams(r, gr.Path, nil)
	r = r.WithContext(setClaims(r.Context(), Claims{UserID: caller}))
	w := httptest.NewRecorder()
	s.generatedGroupHandler(gr).ServeHTTP(w, r)
	return w
}

// TestGroupAPIKeyLifecycle_HTTP: mint -> list (no secret) -> revoke, over the
// real DB through the generated HTTP handlers.
func TestGroupAPIKeyLifecycle_HTTP(t *testing.T) {
	s, pool, caller := newCredTestService(t)
	ctx := context.Background()

	_, err := s.svc.CreatePermissionGroup(ctx, core.CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "m-keys", OwnerSubjectID: caller})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups WHERE persona='merchant' AND instance_slug='m-keys'`)
	})

	mintGR := core.GeneratedRoute{Persona: "merchant", Method: http.MethodPost, Path: "/merchant/:instance_slug/api-keys", Perm: "merchant:api-keys:manage"}
	w := s.drive(t, mintGR, "m-keys", caller, `{"name":"ci","role":"member"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var minted map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &minted))
	require.NotEmpty(t, minted["secret"], "mint must return the secret once")
	require.NotEmpty(t, minted["id"])
	require.Equal(t, "member", minted["role"])
	tokenID, _ := minted["id"].(string)

	// List: secret never present; the minted key is returned.
	listGR := core.GeneratedRoute{Persona: "merchant", Method: http.MethodGet, Path: "/merchant/:instance_slug/api-keys", Perm: "merchant:api-keys:read"}
	w = s.drive(t, listGR, "m-keys", caller, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var listed struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listed))
	require.Len(t, listed.Data, 1)
	_, hasSecret := listed.Data[0]["secret"]
	require.False(t, hasSecret, "list must NOT expose the secret")
	require.Equal(t, tokenID, listed.Data[0]["id"])

	// Revoke by token id (sub-resource path).
	revGR := core.GeneratedRoute{Persona: "merchant", Method: http.MethodDelete, Path: "/merchant/:instance_slug/api-keys/:key", Perm: "merchant:api-keys:manage"}
	repl := strings.NewReplacer(":instance_slug", "m-keys", ":key", tokenID)
	require.Equal(t, http.StatusOK, s.driveSub(t, revGR, repl, caller).Code)

	// Second revoke => 404 (already revoked).
	require.Equal(t, http.StatusNotFound, s.driveSub(t, revGR, repl, caller).Code)
}

// TestGroupRemoteAppLifecycle_HTTP: register -> list-for-group -> delete, over
// the real DB through the generated HTTP handlers, with group scoping enforced.
func TestGroupRemoteAppLifecycle_HTTP(t *testing.T) {
	s, pool, caller := newCredTestService(t)
	ctx := context.Background()

	_, err := s.svc.CreatePermissionGroup(ctx, core.CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "m-apps", OwnerSubjectID: caller})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug LIKE 'ci-ra%'`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups WHERE persona='merchant' AND instance_slug='m-apps'`)
	})

	regGR := core.GeneratedRoute{Persona: "merchant", Method: http.MethodPost, Path: "/merchant/:instance_slug/remote-applications", Perm: "merchant:remote-apps:manage"}
	body := `{"slug":"ci-ra-one","issuer":"https://issuer.ci.example/one","jwks_uri":"https://issuer.ci.example/.well-known/jwks.json","enabled":true}`
	w := s.drive(t, regGR, "m-apps", caller, body)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var reg map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &reg))
	require.Equal(t, "ci-ra-one", reg["slug"])

	// List-for-group returns only this group's apps.
	listGR := core.GeneratedRoute{Persona: "merchant", Method: http.MethodGet, Path: "/merchant/:instance_slug/remote-applications", Perm: "merchant:remote-apps:read"}
	w = s.drive(t, listGR, "m-apps", caller, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var listed struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listed))
	require.Len(t, listed.Data, 1)
	require.Equal(t, "ci-ra-one", listed.Data[0]["slug"])

	// Delete by slug (group-scoped).
	delGR := core.GeneratedRoute{Persona: "merchant", Method: http.MethodDelete, Path: "/merchant/:instance_slug/remote-applications/:app", Perm: "merchant:remote-apps:manage"}
	require.Equal(t, http.StatusOK, s.driveSub(t, delGR, strings.NewReplacer(":instance_slug", "m-apps", ":app", "ci-ra-one"), caller).Code)

	// Now empty.
	w = s.drive(t, listGR, "m-apps", caller, "")
	require.Equal(t, http.StatusOK, w.Code)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listed))
	require.Len(t, listed.Data, 0)
}

// Invite-LINK lifecycle over HTTP (mint -> list -> redeem -> revoke) is covered
// by the #134 link tests; the old user_id invite/accept flow was removed.
