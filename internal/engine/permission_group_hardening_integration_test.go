package engine

import (
	"context"
	"net/http"

	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// #247: permission-group hardening — custom-role no-escalation, hard
// single-role-per-group, 30d invite cap, sentinel HTTP mapping. Exercised
// end-to-end through the generated group-management HTTP routes against a
// real Postgres, mirroring the harness in permission_group_credentials_integration_test.go.

// hardeningTestConfig declares a "merchant" persona with custom roles enabled
// and a catalog so a bounded "roles-admin" role (holds merchant:roles:manage
// but none of the billing perms) can be built for the escalation tests.
func hardeningTestConfig() Config {
	return Config{
		Keys:  testKeys(),
		Token: TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"a"}, ExpectedAudiences: []string{"a"}},
		Roles: RoleConfig{
			Personas: map[string]Persona{"merchant": {
				Permissions: []string{"merchant:billing:read", "merchant:billing:write", "merchant:catalog:read"},
				CustomRoles: true,
			}},
			Roles: []Role{{Persona: "merchant", Name: "roles-admin", Permissions: []string{"merchant:roles:manage"}}},
		},
	}
}

func newHardeningTestService(t *testing.T) (*httpapi.Service, *pgxpool.Pool, string) {
	return newHardeningTestServiceWith(t, hardeningTestConfig())
}

func newHardeningTestServiceWith(t *testing.T, cfg Config) (*httpapi.Service, *pgxpool.Pool, string) {
	t.Helper()
	pool := testdb.Pool(t)
	ctx := context.Background()

	coreSvc, err := coreFromConfig(cfg, pool)
	require.NoError(t, err)
	t.Cleanup(coreSvc.Close)
	_, err = coreSvc.ensureRootGroup(ctx)
	require.NoError(t, err)

	var owner string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO users DEFAULT VALUES RETURNING id::text`).Scan(&owner))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1::uuid`, owner) })

	svc, err := newTestService(coreSvc, httpapi.Config{DisableRateLimiting: true, DirectPeerIP: true})
	require.NoError(t, err)
	t.Cleanup(svc.Close)
	return svc, pool, owner
}

// groupRoute is the group route for op.
func groupRoute(t *testing.T, op httpapi.GroupOp) httpapi.GroupRoute {
	t.Helper()
	for _, gr := range httpapi.GroupRoutes {
		if gr.Op == op {
			return gr
		}
	}
	t.Fatalf("no group route for op %d", op)
	return httpapi.GroupRoute{}
}

// TestCustomRoleRedefineRejectsEscalation_HTTP is the #247 SECURITY fix: a
// bounded actor holding ONLY merchant:roles:manage (not the role's own grants)
// must not be able to redefine (widen or narrow) a custom role — the owner
// (who covers everything) can.
func TestCustomRoleRedefineRejectsEscalation_HTTP(t *testing.T) {
	s, pool, owner := newHardeningTestService(t)
	ctx := context.Background()

	gid, err := seedGroup(ctx, fixtureBackend(s.Backend()), "merchant", owner)
	require.NoError(t, err)
	group := iam.GroupByID(gid)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM permission_groups WHERE id=$1::uuid`, gid)
	})

	var boundedAdmin string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO users DEFAULT VALUES RETURNING id::text`).Scan(&boundedAdmin))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1::uuid`, boundedAdmin) })
	// Unchecked seed of the bounded admin's OWN role — holds
	// roles:manage capability but NONE of the billing perms it will try to touch.
	grantRole(t, fixtureBackend(s.Backend()), group, iam.UserSubject(boundedAdmin), "roles-admin")

	// Owner defines "auditor" (billing:read only) — this establishes a role
	// someone else (in principle) could hold.
	defineGR := groupRoute(t, httpapi.OpRoleDefine)
	w := drive(s, t, defineGR, gid, owner, `{"role":"auditor","permissions":["merchant:billing:read"]}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	// Bounded admin (roles:manage only) attempts to widen it to billing:write
	// too — blocked: the admin doesn't even cover the role's EXISTING grant.
	w = drive(s, t, defineGR, gid, boundedAdmin, `{"role":"auditor","permissions":["merchant:billing:read","merchant:billing:write"]}`)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), string(errmodel.CodeForbidden))

	// The role is UNCHANGED: assigning it and checking effective perms shows
	// only billing:read, never billing:write.
	var subject string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO users DEFAULT VALUES RETURNING id::text`).Scan(&subject))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1::uuid`, subject) })
	grantRole(t, fixtureBackend(s.Backend()), group, iam.UserSubject(subject), "auditor")
	perms, err := effectivePermissions(ctx, fixtureBackend(s.Backend()), iam.UserActor(subject), group)
	require.NoError(t, err)
	require.ElementsMatch(t, []iam.Perm{"merchant:billing:read"}, perms, "escalation attempt must not have widened the stored role")

	// Owner (covers everything) CAN widen it.
	w = drive(s, t, defineGR, gid, owner, `{"role":"auditor","permissions":["merchant:billing:read","merchant:billing:write"]}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	perms, err = effectivePermissions(ctx, fixtureBackend(s.Backend()), iam.UserActor(subject), group)
	require.NoError(t, err)
	require.ElementsMatch(t, []iam.Perm{"merchant:billing:read", "merchant:billing:write"}, perms)

	// Delete is gated symmetrically: the bounded admin still can't cover the
	// role's (now wider) grants, so it cannot delete it either.
	delGR := groupRoute(t, httpapi.OpRoleDelete)
	delRepl := strings.NewReplacer(":group_id", gid, ":role", "auditor")
	dw := driveSub(s, t, delGR, delRepl, boundedAdmin)
	require.Equal(t, http.StatusForbidden, dw.Code, dw.Body.String())

	// Owner CAN delete it.
	dw = driveSub(s, t, delGR, delRepl, owner)
	require.Equal(t, http.StatusOK, dw.Code, dw.Body.String())
	perms, err = effectivePermissions(ctx, fixtureBackend(s.Backend()), iam.UserActor(subject), group)
	require.NoError(t, err)
	require.Empty(t, perms, "after delete, the auditor grant must be gone")
}

// TestCustomRoleRequiresMFA_HTTP: MFA follows permissions. A custom role
// holding a permission the persona marks RequireMFA needs MFA of its holder,
// on the same assignment gate as catalog roles, with no flag to forget.
func TestCustomRoleRequiresMFA_HTTP(t *testing.T) {
	cfg := hardeningTestConfig()
	merchant := cfg.Roles.Personas["merchant"]
	merchant.Permissions = append(merchant.Permissions, "merchant:payouts:send")
	merchant.RequireMFA = []string{"merchant:payouts:send"}
	cfg.Roles.Personas = map[string]Persona{"merchant": merchant}
	s, pool, owner := newHardeningTestServiceWith(t, cfg)
	ctx := context.Background()
	backend := fixtureBackend(s.Backend())

	// The owner holds merchant:*, which reaches the MFA permission.
	_, err := seedGroup(ctx, backend, "merchant", owner)
	require.ErrorIs(t, err, iam.ErrTwoFAEnrollmentRequired)
	_, err = backend.enableFactor(ctx, owner, "email", nil, authflow.AllowAdditionalFactors)
	require.NoError(t, err)
	gid, err := seedGroup(ctx, backend, "merchant", owner)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM permission_groups WHERE id=$1::uuid`, gid)
	})

	defineGR := groupRoute(t, httpapi.OpRoleDefine)
	w := drive(s, t, defineGR, gid, owner, `{"role":"sensitive","permissions":["merchant:payouts:send","merchant:billing:read"]}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	var subject string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO users DEFAULT VALUES RETURNING id::text`).Scan(&subject))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1::uuid`, subject) })

	// Not enrolled in 2FA yet: assignment must be refused (403, 2fa_enrollment_required).
	assignGR := groupRoute(t, httpapi.OpMemberRoleAssign)
	repl := strings.NewReplacer(":group_id", gid, ":user", subject, ":role", "sensitive")
	w = driveSub(s, t, assignGR, repl, owner)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "2fa_enrollment_required")

	// After enrolling, the SAME assignment succeeds.
	_, err = backend.enableFactor(ctx, subject, "email", nil, authflow.AllowAdditionalFactors)
	require.NoError(t, err)
	w = driveSub(s, t, assignGR, repl, owner)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}
