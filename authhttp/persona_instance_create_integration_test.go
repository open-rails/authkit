package authhttp

// #263 e2e (real Postgres, mounted handlers): the generated persona-instance
// creation route (POST /<persona>) — slug pattern, reserved-slug escalation,
// create-or-return-if-member idempotency, velocity limits, the host admission
// seam — and the remote-application role assignment route
// (PUT /<persona>/:instance_slug/remote-applications/:app/roles/:role).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/ratelimit"
	"github.com/stretchr/testify/require"
)

// instanceCreateTestConfig declares an "org" persona with generated creation
// enabled: a slug pattern tighter than the built-in rule (no dots), one
// reserved slug escalated to the root "site-admin" role, and remote
// applications on for the role-assignment route.
func instanceCreateTestConfig() embedded.Config {
	cfg := newServerTestConfig()
	cfg.RBAC = []embedded.PersonaDef{
		{Name: embedded.RootPersona, Roles: []embedded.RoleDef{
			{Name: "site-admin", Permissions: []string{"root:resources:read"}},
		}},
		{
			Name:         "org",
			Parent:       embedded.RootPersona,
			Capabilities: embedded.PersonaCapabilities{RemoteApplications: true},
			Roles: []embedded.RoleDef{
				{Name: "member", Permissions: []string{"org:catalog:read"}},
				{Name: "credential-manager", Permissions: []string{"org:credentials:manage", "org:credentials:read"}},
			},
			Creation: embedded.InstanceCreationDef{
				Enabled:                true,
				SlugPattern:            `[a-z0-9][a-z0-9-]{0,30}`,
				ReservedSlugs:          []string{"platform"},
				ReservedEscalationRole: "site-admin",
			},
		},
	}
	return cfg
}

func newInstanceCreateServer(t *testing.T, opts ...Option) (*Service, *embedded.Client) {
	t.Helper()
	pool := newServerTestPool(t)
	ctx := context.Background()
	client := newServerClient(t, instanceCreateTestConfig(), pool)
	require.NoError(t, client.SeedPermissionGroupContainment(ctx))
	_, err := client.EnsureRootGroup(ctx)
	require.NoError(t, err)
	srv, err := NewServer(client, opts...)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups WHERE persona = 'org'`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_group_slug_tombstones WHERE persona = 'org'`)
	})
	return srv, client
}

func newInstanceTestUser(t *testing.T, srv *Service, prefix string) (id, token string) {
	t.Helper()
	ctx := context.Background()
	user, err := srv.svc.CreateUser(ctx, uniqueEmail(prefix), prefix+uniqueSuffix())
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = srv.svc.Postgres().Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })
	sid, _, _, err := srv.svc.IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	tok, _, err := srv.svc.MintAccessToken(ctx, user.ID, map[string]any{"sid": sid})
	require.NoError(t, err)
	return user.ID, tok
}

type instanceCreateResponse struct {
	OK           bool   `json:"ok"`
	Persona      string `json:"persona"`
	InstanceSlug string `json:"instance_slug"`
	Created      bool   `json:"created"`
}

func postOrg(srv *Service, token, body string) *httptest.ResponseRecorder {
	return serveAuthJSON(srv, http.MethodPost, "/org", body, token)
}

func TestInstanceCreate_RouteMountedOnlyWhenEnabled(t *testing.T) {
	// Creation-enabled persona gets POST /<persona>; a plain persona does not.
	on := newTestServiceWithRBAC(t, instanceCreateTestConfig().RBAC...)
	requireRoute(t, on.APIRoutes(RoutePermissionGroups), http.MethodPost, "/org")

	off := newTestServiceWithRBAC(t, embedded.PersonaDef{
		Name: "team", Parent: embedded.RootPersona,
		Roles: []embedded.RoleDef{{Name: "member", Permissions: []string{"team:catalog:read"}}},
	})
	requireNoRoute(t, off.APIRoutes(RoutePermissionGroups), http.MethodPost, "/team")
}

func TestInstanceCreate_CreateReservedPatternAndIdempotency(t *testing.T) {
	srv, client := newInstanceCreateServer(t, WithoutRateLimiter())
	ctx := context.Background()
	owner, ownerToken := newInstanceTestUser(t, srv, "orgowner")

	// Create: 201, owner seeded from the authenticated subject.
	w := postOrg(srv, ownerToken, `{"slug":"acme","display_name":"Acme"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var res instanceCreateResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	require.True(t, res.Created)
	require.Equal(t, "acme", res.InstanceSlug)
	can, err := client.Can(ctx, owner, embedded.SubjectKindUser, "org", "acme", "org:members:manage")
	require.NoError(t, err)
	require.True(t, can, "creator must hold the owner role in the created instance")

	// Owner re-run: idempotent 200, created=false.
	w = postOrg(srv, ownerToken, `{"slug":"acme"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	res = instanceCreateResponse{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	require.False(t, res.Created)

	// Member re-run: a NON-owner member also gets the idempotent return.
	member, memberToken := newInstanceTestUser(t, srv, "orgmember")
	require.NoError(t, client.Genesis().AssignGroupRole(ctx, "org", "acme", member, embedded.SubjectKindUser, "member"))
	w = postOrg(srv, memberToken, `{"slug":"acme"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	res = instanceCreateResponse{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	require.False(t, res.Created)

	// A stranger gets the conflict.
	_, strangerToken := newInstanceTestUser(t, srv, "orgstranger")
	w = postOrg(srv, strangerToken, `{"slug":"acme"}`)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), string(ErrGroupSlugTaken))

	// Slug matrix: built-in rule violation and pattern violation are both 400.
	for _, slug := range []string{"-bad", "Bad Slug!", "with.dots"} {
		w = postOrg(srv, ownerToken, `{"slug":`+fmt.Sprintf("%q", slug)+`}`)
		require.Equalf(t, http.StatusBadRequest, w.Code, "slug %q: %s", slug, w.Body.String())
		require.Contains(t, w.Body.String(), string(ErrGroupSlugInvalid))
	}
	// Missing slug is a plain invalid request.
	w = postOrg(srv, ownerToken, `{}`)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// Reserved-slug matrix: refused without the escalation role...
	w = postOrg(srv, strangerToken, `{"slug":"platform"}`)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), string(ErrGroupSlugReserved))
	// ...allowed once the caller holds it.
	admin, adminToken := newInstanceTestUser(t, srv, "orgadmin")
	require.NoError(t, client.Genesis().AssignRoleBySlug(ctx, admin, "site-admin"))
	w = postOrg(srv, adminToken, `{"slug":"platform"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	// Machine principals (no user subject) cannot create.
	req := httptest.NewRequest(http.MethodPost, "/org", strings.NewReader(`{"slug":"machine-made"}`))
	rec := httptest.NewRecorder()
	srv.APIHandler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

// serveAuthJSONFrom is serveAuthJSON with a caller-chosen client IP, so the
// per-user velocity cap can be exercised independently of the per-IP one.
func serveAuthJSONFrom(srv *Service, method, path, body, token, remoteAddr string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = remoteAddr
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	srv.APIHandler().ServeHTTP(w, r)
	return w
}

func TestInstanceCreate_VelocityLimits(t *testing.T) {
	srv, _ := newInstanceCreateServer(t, WithRateLimitOverrides(map[string]ratelimit.Limit{
		RLGroupCreate: {Limit: 2, Window: time.Hour},
	}))
	_, token := newInstanceTestUser(t, srv, "orgvelocity")

	// Distinct source IPs per request: the per-IP budget never trips, so the
	// third refusal proves the PER-USER key. (Authkit owns velocity; hosts own
	// cost gates via the admission seam.)
	suffix := uniqueSuffix()
	for i, want := range []int{http.StatusCreated, http.StatusCreated, http.StatusTooManyRequests} {
		addr := fmt.Sprintf("203.0.113.%d:4444", i+1)
		w := serveAuthJSONFrom(srv, http.MethodPost, "/org", fmt.Sprintf(`{"slug":"vel%s-%d"}`, suffix, i), token, addr)
		require.Equalf(t, want, w.Code, "attempt %d: %s", i, w.Body.String())
	}

	// Per-IP budget: two users exhaust one IP's budget; a THIRD user with a
	// fresh per-user budget is still refused from that IP.
	sameIP := "198.51.100.7:4444"
	_, tokenB := newInstanceTestUser(t, srv, "orgvelocityb")
	_, tokenC := newInstanceTestUser(t, srv, "orgvelocityc")
	w := serveAuthJSONFrom(srv, http.MethodPost, "/org", fmt.Sprintf(`{"slug":"velip%s-1"}`, suffix), tokenB, sameIP)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	w = serveAuthJSONFrom(srv, http.MethodPost, "/org", fmt.Sprintf(`{"slug":"velip%s-2"}`, suffix), tokenB, sameIP)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	w = serveAuthJSONFrom(srv, http.MethodPost, "/org", fmt.Sprintf(`{"slug":"velip%s-3"}`, suffix), tokenC, sameIP)
	require.Equal(t, http.StatusTooManyRequests, w.Code, w.Body.String())
}

func TestInstanceCreate_HostAdmissionSeam(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	refuse := errors.New("payment required")
	var refusedSubject string
	client := newServerClient(t, instanceCreateTestConfig(), pool,
		embedded.WithInstanceAdmission(func(_ context.Context, persona, subject string) error {
			if persona == "org" && subject == refusedSubject {
				return refuse
			}
			return nil
		}))
	require.NoError(t, client.SeedPermissionGroupContainment(ctx))
	_, err := client.EnsureRootGroup(ctx)
	require.NoError(t, err)
	srv, err := NewServer(client, WithoutRateLimiter())
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups WHERE persona = 'org'`)
	})

	blocked, blockedToken := newInstanceTestUser(t, srv, "orgblocked")
	refusedSubject = blocked
	w := postOrg(srv, blockedToken, `{"slug":"blocked-co"}`)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), string(ErrGroupCreationRefused))

	_, allowedToken := newInstanceTestUser(t, srv, "orgallowed")
	w = postOrg(srv, allowedToken, `{"slug":"allowed-co"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
}

func TestRemoteApplicationRoleRoute(t *testing.T) {
	srv, client := newInstanceCreateServer(t, WithoutRateLimiter())
	ctx := context.Background()
	_, ownerToken := newInstanceTestUser(t, srv, "orgappowner")

	w := postOrg(srv, ownerToken, `{"slug":"approles"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	gid, err := client.ResolveGroupIDForSlug(ctx, "org", "approles")
	require.NoError(t, err)

	// Register a remote application controlled by the group (dev environment
	// admits the loopback jwks_uri; no fetch happens at registration).
	app, err := client.UpsertRemoteApplication(ctx, authkit.RemoteApplication{
		Slug:              "papp" + uniqueSuffix(),
		PermissionGroupID: gid,
		Issuer:            "https://papp.example.com/" + uniqueSuffix(),
		JWKSURI:           "http://127.0.0.1:9/jwks.json",
		Mode:              "jwks",
		Enabled:           true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.DeleteRemoteApplication(ctx, app.Issuer) })

	rolePath := func(instance, appSlug, role string) string {
		return "/org/" + instance + "/remote-applications/" + appSlug + "/roles/" + role
	}

	// Assign: 200, and the application principal now holds the role's grants.
	w = serveAuthJSON(srv, http.MethodPut, rolePath("approles", app.Slug, "member"), ``, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	can, err := client.Can(ctx, app.ID, embedded.SubjectKindRemoteApp, "org", "approles", "org:catalog:read")
	require.NoError(t, err)
	require.True(t, can, "remote application must hold the assigned role's grants")

	// Unknown role: 400.
	w = serveAuthJSON(srv, http.MethodPut, rolePath("approles", app.Slug, "no-such-role"), ``, ownerToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// Scope: an application controlled by ANOTHER group 404s.
	_, otherToken := newInstanceTestUser(t, srv, "orgappother")
	w = postOrg(srv, otherToken, `{"slug":"otherorg"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	otherGID, err := client.ResolveGroupIDForSlug(ctx, "org", "otherorg")
	require.NoError(t, err)
	foreign, err := client.UpsertRemoteApplication(ctx, authkit.RemoteApplication{
		Slug:              "fapp" + uniqueSuffix(),
		PermissionGroupID: otherGID,
		Issuer:            "https://fapp.example.com/" + uniqueSuffix(),
		JWKSURI:           "http://127.0.0.1:9/jwks.json",
		Mode:              "jwks",
		Enabled:           true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.DeleteRemoteApplication(ctx, foreign.Issuer) })
	w = serveAuthJSON(srv, http.MethodPut, rolePath("approles", foreign.Slug, "member"), ``, ownerToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	// No-escalation: a credential-manager (holds credentials:manage — passes
	// the route gate — but NOT org:catalog:read) cannot hand the app a role
	// conferring authority above their own.
	bounded, boundedToken := newInstanceTestUser(t, srv, "orgappbounded")
	require.NoError(t, client.Genesis().AssignGroupRole(ctx, "org", "approles", bounded, embedded.SubjectKindUser, "credential-manager"))
	w = serveAuthJSON(srv, http.MethodPut, rolePath("approles", app.Slug, "member"), ``, boundedToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// A caller without credentials:manage never reaches the operation (403 at
	// the generated-route gate).
	w = serveAuthJSON(srv, http.MethodPut, rolePath("approles", app.Slug, "member"), ``, otherToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}
