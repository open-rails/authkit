//go:build e2e

package testing

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDevserverRBACE2E exercises the tenant RBAC / service token surface (authkit #46)
// against the REAL devserver binary running in multi-tenant mode with an app
// permission catalog, over real HTTP and a real Postgres. It is the realistic
// replacement for the former in-process http/*_db_test.go suite: tenant/role/
// member/permission state is seeded via psql (no public bootstrap route exists
// for arbitrary state), and every assertion goes through the running server's
// verifier, middleware, and handlers.
//
// The devserver is configured via the override below:
//   - DEVSERVER_ORG_MODE=multi          -> mounts the /tenants/... route group
//   - DEVSERVER_TOKEN_PREFIX=cozy        -> service tokens are "cozy_st_..." branded tokens
//   - DEVSERVER_PERMISSION_CATALOG=...   -> app permissions the catalog accepts
//
// User tokens come from the dev mint endpoint; global-admin is asserted via the
// minted token's global_roles claim (the service token-mint bypass is token-based), while
// tenant membership/roles/permissions are resolved from the DB.
func TestDevserverRBACE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in -short")
	}

	composeBase := findCompose(t)

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	repoRoot := filepath.Dir(wd)

	composeFile := filepath.Join(repoRoot, "docker-compose.devserver.yaml")
	overridePath := filepath.Join(t.TempDir(), "docker-compose.override.yaml")
	project := fmt.Sprintf("authkit_rbac_e2e_%d", time.Now().UnixNano())
	mintSecret := fmt.Sprintf("secret-%d", time.Now().UnixNano())
	aud := "billing-app"

	override := fmt.Sprintf(`services:
  postgres:
    ports: []
  issuer:
    ports:
      - "8080"
    environment:
      DEVSERVER_ORG_MODE: "multi"
      DEVSERVER_TOKEN_PREFIX: "cozy"
      DEVSERVER_PERMISSION_CATALOG: "endpoint:deploy,endpoint:read,repo:read"
      DEVSERVER_DEV_MINT_SECRET: %q
`, mintSecret)
	if err := os.WriteFile(overridePath, []byte(override), 0600); err != nil {
		t.Fatalf("write override: %v", err)
	}

	c := composeCLI{
		base: composeBase,
		dir:  repoRoot,
		env:  []string{"COMPOSE_PROJECT_NAME=" + project},
	}
	t.Cleanup(func() {
		_ = c.runMaybe("-f", composeFile, "-f", overridePath, "down", "-v", "--remove-orphans")
	})
	c.run(t, "-f", composeFile, "-f", overridePath, "up", "-d", "--build", "--remove-orphans")

	rawPort := c.run(t, "-f", composeFile, "-f", overridePath, "port", "issuer", "8080")
	baseURL := "http://127.0.0.1:" + parsePort(t, rawPort)
	api := baseURL + "/api/v1"
	waitForHTTP200(t, baseURL+"/healthz", 90*time.Second)

	// --- low-level helpers ---

	sqlStr := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

	execSQL := func(t *testing.T, sql string) string {
		t.Helper()
		args := []string{"-f", composeFile, "-f", overridePath, "exec", "-T", "postgres",
			"psql", "-U", "admin", "-d", "authkit_db", "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql}
		return strings.TrimSpace(c.run(t, args...))
	}

	// mint returns a user service token via the dev mint endpoint. Pass
	// globalRoles to populate the global_roles claim (e.g. "admin").
	mint := func(t *testing.T, sub string, globalRoles ...string) string {
		t.Helper()
		body := map[string]any{"sub": sub, "aud": aud, "expires_in_seconds": 3600}
		if len(globalRoles) > 0 {
			body["global_roles"] = globalRoles
		}
		resp, raw := httpJSON(t, http.MethodPost, api+"/dev/mint",
			map[string]string{"Authorization": "Bearer " + mintSecret}, body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("dev mint: expected 200, got %d: %s", resp.StatusCode, string(raw))
		}
		var out struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode mint: %v", err)
		}
		if strings.TrimSpace(out.Token) == "" {
			t.Fatalf("dev mint: empty token")
		}
		return out.Token
	}

	req := func(t *testing.T, method, path, bearer, body string) (int, string) {
		t.Helper()
		headers := map[string]string{}
		if bearer != "" {
			headers["Authorization"] = "Bearer " + bearer
		}
		var b any
		if body != "" {
			b = json.RawMessage(body)
		}
		resp, raw := httpJSON(t, method, api+path, headers, b)
		return resp.StatusCode, string(raw)
	}

	mustCode := func(t *testing.T, want, got int, body string) {
		t.Helper()
		if got != want {
			t.Fatalf("expected status %d, got %d: %s", want, got, body)
		}
	}
	has := func(t *testing.T, body, sub string) {
		t.Helper()
		if !strings.Contains(body, sub) {
			t.Fatalf("expected body to contain %q: %s", sub, body)
		}
	}
	decode := func(t *testing.T, body string, v any) {
		t.Helper()
		if err := json.Unmarshal([]byte(body), v); err != nil {
			t.Fatalf("decode %q: %v", body, err)
		}
	}

	// --- seeding helpers (mirror the former service tokenTestEnv) ---

	addUser := func(t *testing.T, username string) string {
		t.Helper()
		return execSQL(t, fmt.Sprintf(
			"INSERT INTO profiles.users (username) VALUES (%s) RETURNING id::text;", sqlStr(username)))
	}
	seedRole := func(t *testing.T, tenantID, role string, perms ...string) {
		t.Helper()
		sql := fmt.Sprintf(
			"INSERT INTO profiles.tenant_roles (tenant_id, role) VALUES (%s::uuid, %s) ON CONFLICT DO NOTHING;",
			sqlStr(tenantID), sqlStr(role))
		for _, p := range perms {
			sql += fmt.Sprintf(
				" INSERT INTO profiles.tenant_role_permissions (tenant_id, role, permission) VALUES (%s::uuid, %s, %s) ON CONFLICT DO NOTHING;",
				sqlStr(tenantID), sqlStr(role), sqlStr(p))
		}
		execSQL(t, sql)
	}
	addMember := func(t *testing.T, tenantID, userID string, roles ...string) {
		t.Helper()
		sql := fmt.Sprintf(
			"INSERT INTO profiles.tenant_memberships (tenant_id, user_id) VALUES (%s::uuid, %s::uuid) ON CONFLICT DO NOTHING;",
			sqlStr(tenantID), sqlStr(userID))
		for _, role := range roles {
			sql += fmt.Sprintf(
				" INSERT INTO profiles.tenant_membership_roles (tenant_id, user_id, role) VALUES (%s::uuid, %s::uuid, %s) ON CONFLICT DO NOTHING;",
				sqlStr(tenantID), sqlStr(userID), sqlStr(role))
		}
		execSQL(t, sql)
	}
	// newTenant creates a fresh tenant and seeds the standard role set used across the
	// ported suite: owner=`*`, deployer, tokenmgr, tokenmgr-noread.
	newTenant := func(t *testing.T) (slug, id string) {
		t.Helper()
		slug = fmt.Sprintf("service token-e2e-%d", time.Now().UnixNano())
		id = execSQL(t, fmt.Sprintf(
			"INSERT INTO profiles.tenants (slug) VALUES (%s) RETURNING id::text;", sqlStr(slug)))
		seedRole(t, id, "owner", "*")
		seedRole(t, id, "deployer", "endpoint:deploy")
		seedRole(t, id, "tokenmgr", "tenant:service_tokens:manage", "endpoint:deploy", "tenant:read")
		seedRole(t, id, "tokenmgr-noread", "tenant:service_tokens:manage", "endpoint:deploy")
		return slug, id
	}

	// ---------------------------------------------------------------------
	// Ported from http/service_tokens_db_test.go
	// ---------------------------------------------------------------------

	t.Run("service token_lifecycle", func(t *testing.T) {
		slug, id := newTenant(t)
		base := "/tenants/" + slug + "/service-tokens"
		owner := addUser(t, "service token-owner-"+slug)
		addMember(t, id, owner, "owner")
		ownerJWT := mint(t, owner)

		// owner holds `*`, so may grant any catalog permission.
		code, body := req(t, http.MethodPost, base, ownerJWT, `{"name":"ci","permissions":["endpoint:deploy","endpoint:read"]}`)
		mustCode(t, http.StatusCreated, code, body)
		var minted struct {
			ID          string   `json:"id"`
			Token       string   `json:"token"`
			Permissions []string `json:"permissions"`
		}
		decode(t, body, &minted)
		has(t, minted.Token, "cozy_st_")
		has(t, body, "endpoint:deploy")
		has(t, body, "endpoint:read")

		// service token authenticates as the tenant with its permissions (service principal).
		code, body = req(t, http.MethodGet, "/dev/whoami", minted.Token, "")
		mustCode(t, http.StatusOK, code, body)
		var who struct {
			Tenant      string   `json:"tenant"`
			Permissions []string `json:"permissions"`
			IsService   bool     `json:"is_service"`
			UserID      string   `json:"user_id"`
		}
		decode(t, body, &who)
		if who.Tenant != slug {
			t.Fatalf("whoami tenant=%q want %q", who.Tenant, slug)
		}
		if !who.IsService {
			t.Fatalf("whoami is_service=false, want true for a service token")
		}
		if who.UserID != "" {
			t.Fatalf("whoami user_id=%q, want empty for a service principal", who.UserID)
		}
		has(t, body, "endpoint:deploy")
		has(t, body, "endpoint:read")

		// A service token cannot mint another service token (management requires a real user).
		code, body = req(t, http.MethodPost, base, minted.Token, `{"name":"x","permissions":["endpoint:deploy"]}`)
		mustCode(t, http.StatusUnauthorized, code, body)

		// Revoke -> the service token stops working -> deleting again is 404.
		code, body = req(t, http.MethodDelete, base+"/"+minted.ID, ownerJWT, "")
		mustCode(t, http.StatusOK, code, body)
		code, body = req(t, http.MethodGet, "/dev/whoami", minted.Token, "")
		mustCode(t, http.StatusUnauthorized, code, body)
		has(t, body, "token_revoked")
		code, body = req(t, http.MethodDelete, base+"/"+minted.ID, ownerJWT, "")
		mustCode(t, http.StatusNotFound, code, body)
	})

	t.Run("service token_mint_authorization", func(t *testing.T) {
		slug, id := newTenant(t)
		base := "/tenants/" + slug + "/service-tokens"
		deployer := addUser(t, "service token-deployer-"+slug)
		addMember(t, id, deployer, "deployer") // endpoint:deploy, NOT tenant:service_tokens:manage
		tokenmgr := addUser(t, "service token-tokenmgr-"+slug)
		addMember(t, id, tokenmgr, "tokenmgr") // tenant:service_tokens:manage + endpoint:deploy + tenant:read

		// caller without tenant:service_tokens:manage cannot mint
		code, body := req(t, http.MethodPost, base, mint(t, deployer), `{"name":"x","permissions":["endpoint:deploy"]}`)
		mustCode(t, http.StatusForbidden, code, body)
		has(t, body, "forbidden")

		// tokenmgr mints a permission it holds
		code, body = req(t, http.MethodPost, base, mint(t, tokenmgr), `{"name":"ok","permissions":["endpoint:deploy"]}`)
		mustCode(t, http.StatusCreated, code, body)

		// no-escalation: tokenmgr cannot grant a permission it lacks
		code, body = req(t, http.MethodPost, base, mint(t, tokenmgr), `{"name":"x","permissions":["endpoint:read"]}`)
		mustCode(t, http.StatusForbidden, code, body)
		has(t, body, "permission_grant_denied")
		has(t, body, "endpoint:read")

		// unknown permission rejected
		code, body = req(t, http.MethodPost, base, mint(t, tokenmgr), `{"name":"x","permissions":["bogus:perm"]}`)
		mustCode(t, http.StatusBadRequest, code, body)
		has(t, body, "unknown_permission")

		// reserved write/mint tenant:* perms are never grantable to a service token
		for _, p := range []string{"tenant:roles:manage", "tenant:members:manage", "tenant:service_tokens:manage"} {
			code, body = req(t, http.MethodPost, base, mint(t, tokenmgr), `{"name":"x","permissions":["`+p+`"]}`)
			mustCode(t, http.StatusForbidden, code, body)
			has(t, body, "permission_not_grantable_to_service_token")
		}

		// read-only tenant:read IS grantable to a service token
		code, body = req(t, http.MethodPost, base, mint(t, tokenmgr), `{"name":"audit-bot","permissions":["tenant:read"]}`)
		mustCode(t, http.StatusCreated, code, body)
		has(t, body, "tenant:read")

		// tenant:read still subject to no-escalation (noread lacks it)
		noread := addUser(t, "service token-noread-"+slug)
		addMember(t, id, noread, "tokenmgr-noread")
		code, body = req(t, http.MethodPost, base, mint(t, noread), `{"name":"x","permissions":["tenant:read"]}`)
		mustCode(t, http.StatusForbidden, code, body)
		has(t, body, "permission_grant_denied")

		// wildcard not grantable to a service token
		code, body = req(t, http.MethodPost, base, mint(t, tokenmgr), `{"name":"x","permissions":["*"]}`)
		mustCode(t, http.StatusForbidden, code, body)
		has(t, body, "permission_not_grantable_to_service_token")

		// global admin (asserted via the token's global_roles claim) may mint any catalog permission
		admin := addUser(t, "service token-gadmin-"+slug)
		code, body = req(t, http.MethodPost, base, mint(t, admin, "admin"), `{"name":"ops","permissions":["endpoint:deploy","endpoint:read","repo:read"]}`)
		mustCode(t, http.StatusCreated, code, body)
	})

	// ---------------------------------------------------------------------
	// Ported from http/tenant_membership_roles_db_test.go
	// ---------------------------------------------------------------------

	t.Run("member_roles_gating_and_no_escalation", func(t *testing.T) {
		slug, id := newTenant(t)
		owner := addUser(t, "mr-owner-"+slug)
		addMember(t, id, owner, "owner")
		ownerJWT := mint(t, owner)

		seedRole(t, id, "memmgr", "tenant:members:manage", "endpoint:deploy")
		memmgr := addUser(t, "mr-memmgr-"+slug)
		addMember(t, id, memmgr, "memmgr")

		target := addUser(t, "mr-target-"+slug)
		addMember(t, id, target, "deployer")
		rolesPath := "/tenants/" + slug + "/members/" + target + "/roles"

		// non-manager (target/deployer lacks tenant:members:manage) cannot assign
		code, body := req(t, http.MethodPost, rolesPath, mint(t, target), `{"role":"deployer"}`)
		mustCode(t, http.StatusForbidden, code, body)
		has(t, body, "forbidden")

		// manager assigns a role within its own permissions
		code, body = req(t, http.MethodPost, rolesPath, mint(t, memmgr), `{"role":"deployer"}`)
		mustCode(t, http.StatusOK, code, body)

		// no-escalation: manager cannot grant the owner role (= *)
		code, body = req(t, http.MethodPost, rolesPath, mint(t, memmgr), `{"role":"owner"}`)
		mustCode(t, http.StatusForbidden, code, body)
		has(t, body, "role_exceeds_grantor")

		// owner (holds *) can grant the owner role
		code, body = req(t, http.MethodPost, rolesPath, ownerJWT, `{"role":"owner"}`)
		mustCode(t, http.StatusOK, code, body)

		// manager can add a member
		newbie := addUser(t, "mr-newbie-"+slug)
		code, body = req(t, http.MethodPost, "/tenants/"+slug+"/members", mint(t, memmgr), `{"user_id":"`+newbie+`"}`)
		mustCode(t, http.StatusOK, code, body)
	})

	// ---------------------------------------------------------------------
	// Ported from http/tenant_role_permissions_db_test.go
	// ---------------------------------------------------------------------

	t.Run("role_permissions_management", func(t *testing.T) {
		slug, id := newTenant(t)
		owner := addUser(t, "rp-owner-"+slug)
		addMember(t, id, owner, "owner")
		ownerJWT := mint(t, owner)

		seedRole(t, id, "rolemgr", "tenant:roles:manage", "endpoint:deploy") // NOT endpoint:read
		rolemgr := addUser(t, "rp-rolemgr-"+slug)
		addMember(t, id, rolemgr, "rolemgr")

		rolePath := func(role string) string { return "/tenants/" + slug + "/roles/" + role }

		// catalog = base UNION app
		code, body := req(t, http.MethodGet, "/permissions", ownerJWT, "")
		mustCode(t, http.StatusOK, code, body)
		has(t, body, "tenant:roles:manage")
		has(t, body, "endpoint:deploy")

		// owner sets a role's permissions, then reads them back
		code, body = req(t, http.MethodPut, rolePath("deployer"), ownerJWT, `{"permissions":["endpoint:deploy"]}`)
		mustCode(t, http.StatusOK, code, body)
		code, body = req(t, http.MethodGet, rolePath("deployer"), ownerJWT, "")
		mustCode(t, http.StatusOK, code, body)
		has(t, body, "endpoint:deploy")

		// PUT create-or-replace defines a brand-new role in one call
		code, body = req(t, http.MethodGet, rolePath("publisher"), ownerJWT, "")
		mustCode(t, http.StatusNotFound, code, body)
		code, body = req(t, http.MethodPut, rolePath("publisher"), ownerJWT, `{"permissions":["repo:read"]}`)
		mustCode(t, http.StatusOK, code, body)
		code, body = req(t, http.MethodGet, rolePath("publisher"), ownerJWT, "")
		mustCode(t, http.StatusOK, code, body)
		var pub struct {
			Role        string   `json:"role"`
			Permissions []string `json:"permissions"`
		}
		decode(t, body, &pub)
		if pub.Role != "publisher" {
			t.Fatalf("role=%q want publisher", pub.Role)
		}
		if len(pub.Permissions) != 1 || pub.Permissions[0] != "repo:read" {
			t.Fatalf("permissions=%v want [repo:read]", pub.Permissions)
		}

		// unknown permission rejected
		code, body = req(t, http.MethodPut, rolePath("deployer"), ownerJWT, `{"permissions":["bogus:perm"]}`)
		mustCode(t, http.StatusBadRequest, code, body)
		has(t, body, "unknown_permission")

		// caller without tenant:roles:manage cannot edit role permissions
		dep := addUser(t, "rp-dep-"+slug)
		addMember(t, id, dep, "deployer")
		code, body = req(t, http.MethodPut, rolePath("deployer"), mint(t, dep), `{"permissions":["endpoint:deploy"]}`)
		mustCode(t, http.StatusForbidden, code, body)
		has(t, body, "forbidden")

		// no-escalation: rolemgr cannot grant a permission it lacks
		code, body = req(t, http.MethodPut, rolePath("deployer"), mint(t, rolemgr), `{"permissions":["endpoint:read"]}`)
		mustCode(t, http.StatusForbidden, code, body)
		has(t, body, "permission_grant_denied")
		has(t, body, "endpoint:read")

		// rolemgr CAN grant a permission it holds
		code, body = req(t, http.MethodPut, rolePath("deployer"), mint(t, rolemgr), `{"permissions":["endpoint:deploy"]}`)
		mustCode(t, http.StatusOK, code, body)

		// member effective permissions (owner = all catalog via *)
		code, body = req(t, http.MethodGet, "/tenants/"+slug+"/members/"+owner+"/permissions", ownerJWT, "")
		mustCode(t, http.StatusOK, code, body)
		has(t, body, "endpoint:deploy")
		has(t, body, "tenant:roles:manage")
	})

	// ---------------------------------------------------------------------
	// Ported from http/org_rbac_introspection_db_test.go
	// ---------------------------------------------------------------------

	t.Run("rbac_introspection", func(t *testing.T) {
		slug, id := newTenant(t)
		owner := addUser(t, "intro-owner-"+slug)
		addMember(t, id, owner, "owner")
		ownerJWT := mint(t, owner)

		dep := addUser(t, "intro-dep-"+slug)
		addMember(t, id, dep, "deployer")
		depJWT := mint(t, dep)

		tenant := "/tenants/" + slug

		// self GET /me returns roles + permissions without tenant:read
		code, body := req(t, http.MethodGet, tenant+"/me", depJWT, "")
		mustCode(t, http.StatusOK, code, body)
		var me struct {
			Roles       []string `json:"roles"`
			Permissions []string `json:"permissions"`
		}
		decode(t, body, &me)
		if len(me.Roles) != 1 || me.Roles[0] != "deployer" {
			t.Fatalf("me.roles=%v want [deployer]", me.Roles)
		}
		if len(me.Permissions) != 1 || me.Permissions[0] != "endpoint:deploy" {
			t.Fatalf("me.permissions=%v want [endpoint:deploy]", me.Permissions)
		}

		// non-member /me is forbidden
		stranger := addUser(t, "intro-stranger-"+slug)
		code, body = req(t, http.MethodGet, tenant+"/me", mint(t, stranger), "")
		mustCode(t, http.StatusForbidden, code, body)

		// permission check (self): granted subset only
		code, body = req(t, http.MethodPost, tenant+"/permissions/check", depJWT, `{"permissions":["endpoint:deploy","endpoint:read","repo:read"]}`)
		mustCode(t, http.StatusOK, code, body)
		var chk struct {
			Granted []string `json:"granted"`
		}
		decode(t, body, &chk)
		if len(chk.Granted) != 1 || chk.Granted[0] != "endpoint:deploy" {
			t.Fatalf("granted=%v want [endpoint:deploy]", chk.Granted)
		}

		// permission check for another member requires tenant:read
		code, body = req(t, http.MethodPost, tenant+"/permissions/check", depJWT, `{"permissions":["endpoint:deploy"],"user_id":"`+owner+`"}`)
		mustCode(t, http.StatusForbidden, code, body)

		// owner can check another member (holds tenant:read via *)
		code, body = req(t, http.MethodPost, tenant+"/permissions/check", ownerJWT, `{"permissions":["endpoint:deploy","endpoint:read"],"user_id":"`+dep+`"}`)
		mustCode(t, http.StatusOK, code, body)
		chk.Granted = nil
		decode(t, body, &chk)
		if len(chk.Granted) != 1 || chk.Granted[0] != "endpoint:deploy" {
			t.Fatalf("granted=%v want [endpoint:deploy] (dep has deploy, not read)", chk.Granted)
		}

		// global admin self-check holds everything requested
		ga := addUser(t, "intro-ga-"+slug) // not even a member
		code, body = req(t, http.MethodPost, tenant+"/permissions/check", mint(t, ga, "admin"), `{"permissions":["endpoint:deploy","repo:read"]}`)
		mustCode(t, http.StatusOK, code, body)
		has(t, body, "endpoint:deploy")
		has(t, body, "repo:read")

		// single-role GET returns name + permissions
		code, body = req(t, http.MethodGet, tenant+"/roles/deployer", ownerJWT, "")
		mustCode(t, http.StatusOK, code, body)
		var role struct {
			Role        string   `json:"role"`
			Permissions []string `json:"permissions"`
		}
		decode(t, body, &role)
		if role.Role != "deployer" || len(role.Permissions) != 1 || role.Permissions[0] != "endpoint:deploy" {
			t.Fatalf("role detail=%+v want deployer/[endpoint:deploy]", role)
		}

		// single-role GET 404 for an undefined role
		code, body = req(t, http.MethodGet, tenant+"/roles/ghost", ownerJWT, "")
		mustCode(t, http.StatusNotFound, code, body)
		has(t, body, "role_not_found")
	})

	t.Run("rbac_deletes_path_param", func(t *testing.T) {
		slug, id := newTenant(t)
		owner := addUser(t, "del-owner-"+slug)
		addMember(t, id, owner, "owner")
		ownerJWT := mint(t, owner)
		tenant := "/tenants/" + slug

		// DELETE role by path param
		seedRole(t, id, "scratch", "endpoint:deploy")
		code, body := req(t, http.MethodDelete, tenant+"/roles/scratch", ownerJWT, "")
		mustCode(t, http.StatusOK, code, body)
		code, body = req(t, http.MethodGet, tenant+"/roles/scratch", ownerJWT, "")
		mustCode(t, http.StatusNotFound, code, body)

		// DELETE protected owner role rejected
		code, body = req(t, http.MethodDelete, tenant+"/roles/owner", ownerJWT, "")
		mustCode(t, http.StatusBadRequest, code, body)
		has(t, body, "protected_role")

		// DELETE member by path param
		victim := addUser(t, "del-victim-"+slug)
		addMember(t, id, victim, "deployer")
		code, body = req(t, http.MethodDelete, tenant+"/members/"+victim, ownerJWT, "")
		mustCode(t, http.StatusOK, code, body)
		code, body = req(t, http.MethodGet, tenant+"/members", ownerJWT, "")
		mustCode(t, http.StatusOK, code, body)
		if strings.Contains(body, victim) {
			t.Fatalf("deleted member %s still listed: %s", victim, body)
		}
	})
}
