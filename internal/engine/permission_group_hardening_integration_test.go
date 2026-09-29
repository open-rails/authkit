package engine

import (
	"context"
	"net/http"

	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// MFA follows permissions on the generated group-management HTTP routes,
// against a real Postgres.

// hardeningTestConfig declares a "merchant" persona whose "sensitive" role
// reaches a permission that needs MFA.
func hardeningTestConfig() Config {
	return Config{
		Keys:  testKeys(),
		Token: TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"a"}, ExpectedAudiences: []string{"a"}},
		Roles: RoleConfig{
			Personas: map[string]Persona{"merchant": {
				Permissions: []string{"merchant:billing:read", "merchant:payouts:send"},
				RequireMFA:  []string{"merchant:payouts:send"},
			}},
			Roles: []Role{{Persona: "merchant", Name: "sensitive", Permissions: []string{"merchant:payouts:send", "merchant:billing:read"}}},
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

	svc, err := newTestService(coreSvc, httpapi.Config{Limiter: unlimited{}, DirectPeerIP: true})
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

// TestRoleRequiresMFA_HTTP: MFA follows permissions. A role holding a
// permission the persona marks RequireMFA needs MFA of its holder on the
// HTTP assignment gate, with no flag to forget.
func TestRoleRequiresMFA_HTTP(t *testing.T) {
	s, pool, owner := newHardeningTestService(t)
	ctx := context.Background()
	backend := fixtureBackend(s.Backend())

	// The owner holds merchant:*, which reaches the MFA permission.
	_, err := seedGroup(ctx, backend, ident.Persona("merchant"), owner)
	require.ErrorIs(t, err, iam.ErrTwoFAEnrollmentRequired)
	_, err = backend.enableFactor(ctx, owner, "email", nil, authflow.AllowAdditionalFactors)
	require.NoError(t, err)
	gid, err := seedGroup(ctx, backend, ident.Persona("merchant"), owner)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM permission_groups WHERE id=$1::uuid`, gid)
	})

	var subject string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO users DEFAULT VALUES RETURNING id::text`).Scan(&subject))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1::uuid`, subject) })

	// Not enrolled in 2FA yet: assignment must be refused (403, 2fa_enrollment_required).
	assignGR := groupRoute(t, httpapi.OpMemberRoleAssign)
	repl := strings.NewReplacer(":group_id", gid, ":user", subject, ":role", "sensitive")
	w := driveSub(s, t, assignGR, repl, owner)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "2fa_enrollment_required")

	// After enrolling, the SAME assignment succeeds.
	_, err = backend.enableFactor(ctx, subject, "email", nil, authflow.AllowAdditionalFactors)
	require.NoError(t, err)
	w = driveSub(s, t, assignGR, repl, owner)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}
