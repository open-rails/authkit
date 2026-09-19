package authhttp

import (
	"context"
	"encoding/json"
	"net/http"

	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// #247: permission-group hardening — custom-role no-escalation, hard
// single-role-per-group, 30d invite cap, sentinel HTTP mapping. Exercised
// end-to-end through the generated group-management HTTP routes against a
// real Postgres, mirroring the harness in permission_group_credentials_integration_test.go.

// hardeningTestConfig declares a "merchant" persona with custom roles enabled
// and an explicit Catalog so a bounded "roles-admin" role (holds
// merchant:roles:manage but none of the billing perms) can be built for the
// escalation tests.
func hardeningTestConfig() embedded.Config {
	return embedded.Config{
		Keys:  testKeys(),
		Token: embedded.TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"a"}, ExpectedAudiences: []string{"a"}},
		RBAC: []embedded.PersonaDef{{
			Name: "merchant", Parent: authkit.RootPersona,
			Capabilities: embedded.PersonaCapabilities{CustomRoles: true},
			Catalog:      []string{"merchant:billing:read", "merchant:billing:write", "merchant:catalog:read", "merchant:roles:manage"},
			Roles: []embedded.RoleDef{
				{Name: "roles-admin", Permissions: []string{"merchant:roles:manage"}},
			},
		}},
	}
}

func newHardeningTestService(t *testing.T) (*Service, *pgxpool.Pool, string) {
	t.Helper()
	pool := testdb.Pool(t)
	ctx := context.Background()

	coreSvc, err := coreFromConfig(hardeningTestConfig(), pool)
	require.NoError(t, err)
	require.NoError(t, coreSvc.SeedPermissionGroupContainment(ctx))
	_, err = coreSvc.EnsureRootGroup(ctx)
	require.NoError(t, err)

	var owner string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO users DEFAULT VALUES RETURNING id::text`).Scan(&owner))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1::uuid`, owner) })

	return &Service{svc: coreSvc}, pool, owner
}

func defineRoleGR(persona string) embedded.GeneratedRoute {
	return embedded.GeneratedRoute{Persona: authkit.Persona(persona), Method: http.MethodPost, Path: "/" + persona + "/:instance_slug/roles", Perm: "merchant:roles:manage"}
}

func deleteRoleGR(persona string) embedded.GeneratedRoute {
	return embedded.GeneratedRoute{Persona: authkit.Persona(persona), Method: http.MethodDelete, Path: "/" + persona + "/:instance_slug/roles/:role", Perm: "merchant:roles:manage"}
}

func memberRoleAssignGR(persona string) embedded.GeneratedRoute {
	return embedded.GeneratedRoute{Persona: authkit.Persona(persona), Method: http.MethodPut, Path: "/" + persona + "/:instance_slug/members/:user/roles/:role", Perm: "merchant:members:manage"}
}

// TestCustomRoleRedefineRejectsEscalation_HTTP is the #247 SECURITY fix: a
// bounded actor holding ONLY merchant:roles:manage (not the role's own grants)
// must not be able to redefine (widen or narrow) a custom role — the owner
// (who covers everything) can.
func TestCustomRoleRedefineRejectsEscalation_HTTP(t *testing.T) {
	s, pool, owner := newHardeningTestService(t)
	ctx := context.Background()

	_, err := s.svc.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "m-escalate", OwnerSubjectID: owner})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM permission_groups WHERE persona='merchant' AND instance_slug='m-escalate'`)
	})

	var boundedAdmin string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO users DEFAULT VALUES RETURNING id::text`).Scan(&boundedAdmin))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1::uuid`, boundedAdmin) })
	// Genesis-style unchecked seed of the bounded admin's OWN role — holds
	// roles:manage capability but NONE of the billing perms it will try to touch.
	require.NoError(t, s.svc.AssignGroupRole(ctx, authkit.GroupRef{Persona: "merchant", Instance: "m-escalate"}, authkit.UserSubject(boundedAdmin), "roles-admin"))

	// Owner defines "auditor" (billing:read only) — this establishes a role
	// someone else (in principle) could hold.
	defineGR := defineRoleGR("merchant")
	w := s.drive(t, defineGR, "m-escalate", owner, `{"role":"auditor","permissions":["merchant:billing:read"]}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	// Bounded admin (roles:manage only) attempts to widen it to billing:write
	// too — blocked: the admin doesn't even cover the role's EXISTING grant.
	w = s.drive(t, defineGR, "m-escalate", boundedAdmin, `{"role":"auditor","permissions":["merchant:billing:read","merchant:billing:write"]}`)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), string(authkit.CodeForbidden))

	// The role is UNCHANGED: assigning it and checking effective perms shows
	// only billing:read, never billing:write.
	var subject string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO users DEFAULT VALUES RETURNING id::text`).Scan(&subject))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1::uuid`, subject) })
	require.NoError(t, s.svc.AssignGroupRole(ctx, authkit.GroupRef{Persona: "merchant", Instance: "m-escalate"}, authkit.UserSubject(subject), "auditor"))
	perms, err := s.svc.ListEffectivePermissions(ctx, authkit.UserSubject(subject), authkit.GroupRef{Persona: "merchant", Instance: "m-escalate"})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"merchant:billing:read"}, perms, "escalation attempt must not have widened the stored role")

	// Owner (covers everything) CAN widen it.
	w = s.drive(t, defineGR, "m-escalate", owner, `{"role":"auditor","permissions":["merchant:billing:read","merchant:billing:write"]}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	perms, err = s.svc.ListEffectivePermissions(ctx, authkit.UserSubject(subject), authkit.GroupRef{Persona: "merchant", Instance: "m-escalate"})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"merchant:billing:read", "merchant:billing:write"}, perms)

	// Delete is gated symmetrically: the bounded admin still can't cover the
	// role's (now wider) grants, so it cannot delete it either.
	delGR := deleteRoleGR("merchant")
	delRepl := strings.NewReplacer(":instance_slug", "m-escalate", ":role", "auditor")
	dw := s.driveSub(t, delGR, delRepl, boundedAdmin)
	require.Equal(t, http.StatusForbidden, dw.Code, dw.Body.String())

	// Owner CAN delete it.
	dw = s.driveSub(t, delGR, delRepl, owner)
	require.Equal(t, http.StatusOK, dw.Code, dw.Body.String())
	perms, err = s.svc.ListEffectivePermissions(ctx, authkit.UserSubject(subject), authkit.GroupRef{Persona: "merchant", Instance: "m-escalate"})
	require.NoError(t, err)
	require.Empty(t, perms, "after delete, the auditor grant must be gone")
}

// TestCustomRoleRequiresMFA_HTTP: #247 — a custom role can declare
// requires_mfa, honored by the SAME assignment-time MFA gate as catalog roles.
func TestCustomRoleRequiresMFA_HTTP(t *testing.T) {
	s, pool, owner := newHardeningTestService(t)
	ctx := context.Background()

	_, err := s.svc.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "m-mfa-role", OwnerSubjectID: owner})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM permission_groups WHERE persona='merchant' AND instance_slug='m-mfa-role'`)
	})

	defineGR := defineRoleGR("merchant")
	w := s.drive(t, defineGR, "m-mfa-role", owner, `{"role":"sensitive","permissions":["merchant:billing:read"],"requires_mfa":true}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	require.Equal(t, true, created["requires_mfa"])

	var subject string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO users DEFAULT VALUES RETURNING id::text`).Scan(&subject))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1::uuid`, subject) })

	// Not enrolled in 2FA yet: assignment must be refused (403, 2fa_enrollment_required).
	assignGR := memberRoleAssignGR("merchant")
	repl := strings.NewReplacer(":instance_slug", "m-mfa-role", ":user", subject, ":role", "sensitive")
	w = s.driveSub(t, assignGR, repl, owner)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "2fa_enrollment_required")

	// After enrolling, the SAME assignment succeeds.
	_, err = s.svc.Enable2FA(ctx, subject, "email", nil, embedded.AllowAdditionalFactors)
	require.NoError(t, err)
	w = s.driveSub(t, assignGR, repl, owner)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}
