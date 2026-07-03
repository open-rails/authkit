package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/stretchr/testify/require"
)

// credTestConfig enables the credential/invite management capabilities under
// test: a "merchant" persona with api-key minting, remote-app registration, and
// invitations, plus a role catalog the keys/invites can reference. Passed via
// RBAC so authcore.NewFromConfig builds + installs the schema.
func credTestConfig() embedded.Config {
	return embedded.Config{
		Keys:  embedded.KeysConfig{AllowEphemeralDevKeys: true}, // #231: tests opt in explicitly
		Token: embedded.TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"a"}, ExpectedAudiences: []string{"a"}},
		RBAC: []embedded.PersonaDef{{
			Name: "merchant", Parent: embedded.RootPersona,
			Capabilities: embedded.PersonaCapabilities{APIKeys: true, RemoteApplications: true},
			Roles: []embedded.RoleDef{
				{Name: "member", Permissions: []string{"merchant:catalog:read"}},
				{Name: "credential-manager", Permissions: []string{"merchant:credentials:manage"}},
			},
		}},
	}
}

// newCredTestService builds an http.Service over a REAL pool with the credential
// schema, seeds containment + root group, and stubs the authorizer to allow (the
// gate is covered by the no-DB route tests; here we exercise the DB-backed ops).
// Returns the service, the pool, and a freshly-created user id to act as caller.
func newCredTestService(t *testing.T) (*Service, *pgxpool.Pool, string) {
	return newCredTestServiceWithOptions(t)
}

func newCredTestServiceWithOptions(t *testing.T, opts ...authcore.Option) (*Service, *pgxpool.Pool, string) {
	t.Helper()
	pool := newServerTestPool(t)
	ctx := context.Background()

	coreSvc, err := authcore.NewFromConfig(credTestConfig(), pool, opts...)
	require.NoError(t, err)
	require.NoError(t, coreSvc.SeedPermissionGroupContainment(ctx))
	_, err = coreSvc.EnsureRootGroup(ctx)
	require.NoError(t, err)

	var caller string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(&caller))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id = $1::uuid`, caller) })

	return &Service{svc: coreSvc}, pool, caller
}

func newInviteOnlyCredTestService(t *testing.T) (*Service, *pgxpool.Pool, string) {
	t.Helper()
	pool := newServerTestPool(t)
	ctx := context.Background()

	cfg := credTestConfig()
	cfg.Registration.NativeUserMode = embedded.RegistrationModeInviteOnly
	coreSvc, err := authcore.NewFromConfig(cfg, pool)
	require.NoError(t, err)
	require.NoError(t, coreSvc.SeedPermissionGroupContainment(ctx))
	_, err = coreSvc.EnsureRootGroup(ctx)
	require.NoError(t, err)

	var caller string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(&caller))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id = $1::uuid`, caller) })

	return &Service{svc: coreSvc}, pool, caller
}

// drive runs one generated route handler at a concrete (no sub-resource) path,
// with the caller's claims set, and returns the recorder. Sub-resource DELETEs
// (:key / :app / :invite) are driven inline via driveSub.
func (s *Service) drive(t *testing.T, gr embedded.GeneratedRoute, instanceSlug, caller, body string) *httptest.ResponseRecorder {
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
func (s *Service) driveSub(t *testing.T, gr embedded.GeneratedRoute, repl *strings.Replacer, caller string) *httptest.ResponseRecorder {
	t.Helper()
	path := repl.Replace(gr.Path)
	r := httptest.NewRequest(gr.Method, "http://x"+path, nil)
	r = withMuxParams(r, gr.Path, nil)
	r = r.WithContext(setClaims(r.Context(), Claims{UserID: caller}))
	w := httptest.NewRecorder()
	s.generatedGroupHandler(gr).ServeHTTP(w, r)
	return w
}

func TestGroupMembersListUsesSnakeCaseJSON_HTTP(t *testing.T) {
	s, pool, caller := newCredTestService(t)
	ctx := context.Background()

	_, err := s.svc.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "m-members", OwnerSubjectID: caller})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups WHERE persona='merchant' AND instance_slug='m-members'`)
	})

	listGR := embedded.GeneratedRoute{Persona: "merchant", Method: http.MethodGet, Path: "/merchant/:instance_slug/members", Perm: "merchant:roles:read"}
	w := s.drive(t, listGR, "m-members", caller, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var listed struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listed))
	require.NotEmpty(t, listed.Data)
	require.Equal(t, caller, listed.Data[0]["subject_id"])
	require.Equal(t, "user", listed.Data[0]["subject_kind"])
	require.NotContains(t, listed.Data[0], "subject-id")
	require.NotContains(t, listed.Data[0], "subject-kind")
}

// #147 register+join: adding an UNKNOWN email under a group's members:manage mints
// ONE role-carrying account-registration invite (not two separate tokens). Consuming
// the code registers the stranger AND grants the carried role on consume. The handler
// returns it under "invite" (the legacy "group_invite" key is gone), and the stored
// row references the permission group + role it will grant.
func TestGroupMemberAddUnknownEmailMintsRoleCarryingAccountInvite_HTTP(t *testing.T) {
	s, pool, caller := newInviteOnlyCredTestService(t)
	ctx := context.Background()

	_, err := s.svc.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "m-invites", OwnerSubjectID: caller})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups WHERE persona='merchant' AND instance_slug='m-invites'`)
	})

	email := uniqueEmail("member-invite")
	addGR := embedded.GeneratedRoute{Persona: "merchant", Method: http.MethodPost, Path: "/merchant/:instance_slug/members", Perm: "merchant:members:manage"}
	w := s.drive(t, addGR, "m-invites", caller, `{"email":"`+email+`","role":"member"}`)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Equal(t, true, resp["invited"])
	// One role-carrying account-registration invite, returned under "invite".
	invite, ok := resp["invite"].(map[string]any)
	require.True(t, ok, "expected an invite object, got: %s", w.Body.String())
	require.NotEmpty(t, invite["code"])
	require.NotContains(t, resp, "group_invite") // legacy two-token key is gone

	// Exactly one account-registration invite, carrying the group + role to grant
	// on consume (register+join), minted under members:manage (not root:users:invite).
	var count int
	var role string
	var hasGroup bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*), coalesce(max(role), ''), coalesce(bool_or(permission_group_id IS NOT NULL), false)
		   FROM profiles.account_registration_invites WHERE email=$1`, email).Scan(&count, &role, &hasGroup))
	require.Equal(t, 1, count)
	require.Equal(t, "member", role)
	require.True(t, hasGroup, "register+join invite must reference the permission group")
}

// TestGroupAPIKeyLifecycle_HTTP: mint -> list (no secret) -> revoke, over the
// real DB through the generated HTTP handlers.
func TestGroupAPIKeyLifecycle_HTTP(t *testing.T) {
	s, pool, caller := newCredTestService(t)
	ctx := context.Background()

	_, err := s.svc.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "m-keys", OwnerSubjectID: caller})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups WHERE persona='merchant' AND instance_slug='m-keys'`)
	})

	mintGR := embedded.GeneratedRoute{Persona: "merchant", Method: http.MethodPost, Path: "/merchant/:instance_slug/api-keys", Perm: "merchant:credentials:manage"}
	w := s.drive(t, mintGR, "m-keys", caller, `{"name":"ci","role":"member"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var minted map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &minted))
	require.NotEmpty(t, minted["secret"], "mint must return the secret once")
	require.NotEmpty(t, minted["id"])
	require.Equal(t, "member", minted["role"])
	tokenID, _ := minted["id"].(string)

	// List: secret never present; the minted key is returned.
	listGR := embedded.GeneratedRoute{Persona: "merchant", Method: http.MethodGet, Path: "/merchant/:instance_slug/api-keys", Perm: "merchant:credentials:read"}
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
	revGR := embedded.GeneratedRoute{Persona: "merchant", Method: http.MethodDelete, Path: "/merchant/:instance_slug/api-keys/:key", Perm: "merchant:credentials:manage"}
	repl := strings.NewReplacer(":instance_slug", "m-keys", ":key", tokenID)
	require.Equal(t, http.StatusOK, s.driveSub(t, revGR, repl, caller).Code)

	// Second revoke => 404 (already revoked).
	require.Equal(t, http.StatusNotFound, s.driveSub(t, revGR, repl, caller).Code)
}

func TestGroupAPIKeyMintRejectsRoleEscalation_HTTP(t *testing.T) {
	s, pool, caller := newCredTestService(t)
	ctx := context.Background()

	_, err := s.svc.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "m-role-denied", OwnerSubjectID: caller})
	require.NoError(t, err)
	var weakActor string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(&weakActor))
	require.NoError(t, s.svc.AssignGroupRole(ctx, "merchant", "m-role-denied", weakActor, embedded.SubjectKindUser, "credential-manager"))
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id = $1::uuid`, weakActor)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups WHERE persona='merchant' AND instance_slug='m-role-denied'`)
	})

	mintGR := embedded.GeneratedRoute{Persona: "merchant", Method: http.MethodPost, Path: "/merchant/:instance_slug/api-keys", Perm: "merchant:credentials:manage"}
	w := s.drive(t, mintGR, "m-role-denied", weakActor, `{"name":"escalate-role","role":"member"}`)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), string(ErrForbidden))

	listGR := embedded.GeneratedRoute{Persona: "merchant", Method: http.MethodGet, Path: "/merchant/:instance_slug/api-keys", Perm: "merchant:credentials:read"}
	w = s.drive(t, listGR, "m-role-denied", caller, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var listed struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listed))
	require.Len(t, listed.Data, 0, "denied API-key role escalation must not mint a key")
}

// TestGroupRemoteAppLifecycle_HTTP: register -> list-for-group -> delete, over
// the real DB through the generated HTTP handlers, with group scoping enforced.
func TestGroupRemoteAppLifecycle_HTTP(t *testing.T) {
	s, pool, caller := newCredTestService(t)
	ctx := context.Background()

	_, err := s.svc.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "m-apps", OwnerSubjectID: caller})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug LIKE 'ci-ra%'`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups WHERE persona='merchant' AND instance_slug='m-apps'`)
	})

	regGR := embedded.GeneratedRoute{Persona: "merchant", Method: http.MethodPost, Path: "/merchant/:instance_slug/remote-applications", Perm: "merchant:credentials:manage"}
	body := `{"slug":"ci-ra-one","issuer":"https://issuer.ci.example/one","jwks_uri":"https://issuer.ci.example/.well-known/jwks.json","enabled":true}`
	w := s.drive(t, regGR, "m-apps", caller, body)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var reg map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &reg))
	require.Equal(t, "ci-ra-one", reg["slug"])

	// List-for-group returns only this group's apps.
	listGR := embedded.GeneratedRoute{Persona: "merchant", Method: http.MethodGet, Path: "/merchant/:instance_slug/remote-applications", Perm: "merchant:credentials:read"}
	w = s.drive(t, listGR, "m-apps", caller, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var listed struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listed))
	require.Len(t, listed.Data, 1)
	require.Equal(t, "ci-ra-one", listed.Data[0]["slug"])

	// Delete by slug (group-scoped).
	delGR := embedded.GeneratedRoute{Persona: "merchant", Method: http.MethodDelete, Path: "/merchant/:instance_slug/remote-applications/:app", Perm: "merchant:credentials:manage"}
	require.Equal(t, http.StatusOK, s.driveSub(t, delGR, strings.NewReplacer(":instance_slug", "m-apps", ":app", "ci-ra-one"), caller).Code)

	// Now empty.
	w = s.drive(t, listGR, "m-apps", caller, "")
	require.Equal(t, http.StatusOK, w.Code)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listed))
	require.Len(t, listed.Data, 0)
}

// Regression: omitting "enabled" on a re-register (upsert) must NOT silently
// disable an already-enabled issuer. The request field was a plain bool that
// collapsed "field omitted" into false; it is now a *bool defaulting to true
// when absent, while an explicit false still disables the issuer.
func TestGroupRemoteAppRegisterEnabledOmitted_HTTP(t *testing.T) {
	s, pool, caller := newCredTestService(t)
	ctx := context.Background()

	_, err := s.svc.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "m-en", OwnerSubjectID: caller})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug LIKE 'ci-en%'`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups WHERE persona='merchant' AND instance_slug='m-en'`)
	})

	regGR := embedded.GeneratedRoute{Persona: "merchant", Method: http.MethodPost, Path: "/merchant/:instance_slug/remote-applications", Perm: "merchant:credentials:manage"}
	register := func(t *testing.T, body string) map[string]any {
		t.Helper()
		w := s.drive(t, regGR, "m-en", caller, body)
		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
		var out map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
		return out
	}

	const issuer = "https://issuer.ci.example/en"

	// 1. Initial register, explicitly enabled.
	reg := register(t, `{"slug":"ci-en","issuer":"`+issuer+`","jwks_uri":"https://issuer.ci.example/.well-known/jwks.json","enabled":true}`)
	require.Equal(t, true, reg["enabled"])

	// 2. Partial re-register (rotate jwks_uri) that OMITS "enabled": must stay enabled.
	reg = register(t, `{"slug":"ci-en","issuer":"`+issuer+`","jwks_uri":"https://issuer.ci.example/rotated/jwks.json"}`)
	require.Equal(t, true, reg["enabled"], "omitting enabled must not disable an existing issuer")

	// 3. Explicit enabled:false must still disable (guards the intended disable path).
	reg = register(t, `{"slug":"ci-en","issuer":"`+issuer+`","jwks_uri":"https://issuer.ci.example/rotated/jwks.json","enabled":false}`)
	require.Equal(t, false, reg["enabled"], "explicit enabled:false must still disable")
}

// Invite-LINK lifecycle over HTTP (mint -> list -> redeem -> revoke) is covered
// by the #134 link tests; the old user_id invite/accept flow was removed.
