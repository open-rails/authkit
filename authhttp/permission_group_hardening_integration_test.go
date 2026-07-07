package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
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
		Keys:  embedded.KeysConfig{AllowEphemeralDevKeys: true},
		Token: embedded.TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"a"}, ExpectedAudiences: []string{"a"}},
		RBAC: []embedded.PersonaDef{{
			Name: "merchant", Parent: embedded.RootPersona,
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
	pool := newServerTestPool(t)
	ctx := context.Background()

	coreSvc, err := authcore.NewFromConfig(hardeningTestConfig(), pool)
	require.NoError(t, err)
	require.NoError(t, coreSvc.SeedPermissionGroupContainment(ctx))
	_, err = coreSvc.EnsureRootGroup(ctx)
	require.NoError(t, err)

	var owner string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(&owner))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id = $1::uuid`, owner) })

	return &Service{svc: coreSvc}, pool, owner
}

func defineRoleGR(persona string) embedded.GeneratedRoute {
	return embedded.GeneratedRoute{Persona: persona, Method: http.MethodPost, Path: "/" + persona + "/:instance_slug/roles", Perm: "merchant:roles:manage"}
}

func deleteRoleGR(persona string) embedded.GeneratedRoute {
	return embedded.GeneratedRoute{Persona: persona, Method: http.MethodDelete, Path: "/" + persona + "/:instance_slug/roles/:role", Perm: "merchant:roles:manage"}
}

func memberRoleAssignGR(persona string) embedded.GeneratedRoute {
	return embedded.GeneratedRoute{Persona: persona, Method: http.MethodPut, Path: "/" + persona + "/:instance_slug/members/:user/roles/:role", Perm: "merchant:members:manage"}
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
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups WHERE persona='merchant' AND instance_slug='m-escalate'`)
	})

	var boundedAdmin string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(&boundedAdmin))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id = $1::uuid`, boundedAdmin) })
	// Genesis-style unchecked seed of the bounded admin's OWN role — holds
	// roles:manage capability but NONE of the billing perms it will try to touch.
	require.NoError(t, s.svc.AssignGroupRole(ctx, "merchant", "m-escalate", boundedAdmin, embedded.SubjectKindUser, "roles-admin"))

	// Owner defines "auditor" (billing:read only) — this establishes a role
	// someone else (in principle) could hold.
	defineGR := defineRoleGR("merchant")
	w := s.drive(t, defineGR, "m-escalate", owner, `{"role":"auditor","permissions":["merchant:billing:read"]}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	// Bounded admin (roles:manage only) attempts to widen it to billing:write
	// too — blocked: the admin doesn't even cover the role's EXISTING grant.
	w = s.drive(t, defineGR, "m-escalate", boundedAdmin, `{"role":"auditor","permissions":["merchant:billing:read","merchant:billing:write"]}`)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), string(ErrForbidden))

	// The role is UNCHANGED: assigning it and checking effective perms shows
	// only billing:read, never billing:write.
	var subject string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(&subject))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id = $1::uuid`, subject) })
	require.NoError(t, s.svc.AssignGroupRole(ctx, "merchant", "m-escalate", subject, embedded.SubjectKindUser, "auditor"))
	perms, err := s.svc.ListEffectivePermissions(ctx, subject, embedded.SubjectKindUser, "merchant", "m-escalate")
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"merchant:billing:read"}, perms, "escalation attempt must not have widened the stored role")

	// Owner (covers everything) CAN widen it.
	w = s.drive(t, defineGR, "m-escalate", owner, `{"role":"auditor","permissions":["merchant:billing:read","merchant:billing:write"]}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	perms, err = s.svc.ListEffectivePermissions(ctx, subject, embedded.SubjectKindUser, "merchant", "m-escalate")
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
	perms, err = s.svc.ListEffectivePermissions(ctx, subject, embedded.SubjectKindUser, "merchant", "m-escalate")
	require.NoError(t, err)
	require.Empty(t, perms, "after delete, the auditor grant must be gone")
}

// TestCustomRoleDefineRejectsInvalidInput_HTTP exercises the #247 sentinel
// mapping (errors.Is, replacing strings.Contains) end-to-end: every validation
// failure on the define route surfaces as 400 invalid_request.
func TestCustomRoleDefineRejectsInvalidInput_HTTP(t *testing.T) {
	s, pool, owner := newHardeningTestService(t)
	ctx := context.Background()

	_, err := s.svc.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "m-sentinels", OwnerSubjectID: owner})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups WHERE persona='merchant' AND instance_slug='m-sentinels'`)
	})

	defineGR := defineRoleGR("merchant")
	cases := []struct {
		name string
		body string
	}{
		{"bad role name", `{"role":"Bad_Name!","permissions":["merchant:billing:read"]}`},
		{"cross-persona grant", `{"role":"x1","permissions":["root:users:ban"]}`},
		{"outside catalog", `{"role":"x2","permissions":["merchant:secret:read"]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := s.drive(t, defineGR, "m-sentinels", owner, c.body)
			require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			require.Contains(t, w.Body.String(), string(ErrInvalidRequest))
		})
	}
}

// TestSingleRolePerGroupReplacesNotUnions_HTTP: #247 hard rule — assigning a
// second role to a subject already holding one in the SAME group REPLACES it
// (never a union); the subject ends up with only the latest role's grants.
func TestSingleRolePerGroupReplacesNotUnions_HTTP(t *testing.T) {
	s, pool, owner := newHardeningTestService(t)
	ctx := context.Background()

	_, err := s.svc.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "m-single-role", OwnerSubjectID: owner})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups WHERE persona='merchant' AND instance_slug='m-single-role'`)
	})

	var subject string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(&subject))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id = $1::uuid`, subject) })

	assignGR := memberRoleAssignGR("merchant")
	repl1 := strings.NewReplacer(":instance_slug", "m-single-role", ":user", subject, ":role", "roles-admin")
	require.Equal(t, http.StatusOK, s.driveSub(t, assignGR, repl1, owner).Code)

	perms, err := s.svc.ListEffectivePermissions(ctx, subject, embedded.SubjectKindUser, "merchant", "m-single-role")
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"merchant:roles:manage"}, perms)

	// Assign a SECOND role in the SAME group: replaces, never unions.
	require.NoError(t, s.svc.DefineGroupCustomRole(ctx, owner, "merchant", "m-single-role", "auditor", []string{"merchant:billing:read"}, false))
	repl2 := strings.NewReplacer(":instance_slug", "m-single-role", ":user", subject, ":role", "auditor")
	require.Equal(t, http.StatusOK, s.driveSub(t, assignGR, repl2, owner).Code)

	perms, err = s.svc.ListEffectivePermissions(ctx, subject, embedded.SubjectKindUser, "merchant", "m-single-role")
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"merchant:billing:read"}, perms, "second role must REPLACE the first, never union")

	members, err := s.svc.ListGroupMembers(ctx, "merchant", "m-single-role")
	require.NoError(t, err)
	roleCount := 0
	for _, m := range members {
		if m.SubjectID == subject {
			roleCount++
		}
	}
	require.Equal(t, 1, roleCount, "the subject must appear exactly once (one live role) in the group roster")
}

// TestInviteLinkExpiryClampedTo30Days_HTTP: #247 — a mint request for longer
// than 30 days is CLAMPED to now+30d, never rejected outright and never
// honored as requested.
func TestInviteLinkExpiryClampedTo30Days_HTTP(t *testing.T) {
	s, pool, owner := newHardeningTestService(t)
	ctx := context.Background()

	_, err := s.svc.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "m-invite-ttl", OwnerSubjectID: owner})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups WHERE persona='merchant' AND instance_slug='m-invite-ttl'`)
	})

	mintGR := embedded.GeneratedRoute{Persona: "merchant", Method: http.MethodPost, Path: "/merchant/:instance_slug/invites/links", Perm: "merchant:members:manage"}
	// Request 90 days — must clamp to 30.
	ninetyDaysSeconds := int64(90 * 24 * 3600)
	body := `{"role":"roles-admin","expires_in_seconds":` + strconv.FormatInt(ninetyDaysSeconds, 10) + `}`
	w := s.drive(t, mintGR, "m-invite-ttl", owner, body)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	links, err := s.svc.ListGroupInviteLinks(ctx, "merchant", "m-invite-ttl")
	require.NoError(t, err)
	require.Len(t, links, 1)
	require.NotNil(t, links[0].ExpiresAt)
	maxAllowed := time.Now().UTC().Add(31 * 24 * time.Hour) // 30d ceiling + slack for test runtime
	require.Truef(t, links[0].ExpiresAt.Before(maxAllowed),
		"invite expiry %v must be clamped to ~30d, not the requested 90d", links[0].ExpiresAt)
	minExpected := time.Now().UTC().Add(29 * 24 * time.Hour)
	require.Truef(t, links[0].ExpiresAt.After(minExpected),
		"invite expiry %v should still be close to the 30d ceiling, not some much-shorter accidental default", links[0].ExpiresAt)
}

// TestCustomRoleRequiresMFA_HTTP: #247 — a custom role can declare
// requires_mfa, honored by the SAME assignment-time MFA gate as catalog roles.
func TestCustomRoleRequiresMFA_HTTP(t *testing.T) {
	s, pool, owner := newHardeningTestService(t)
	ctx := context.Background()

	_, err := s.svc.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "m-mfa-role", OwnerSubjectID: owner})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups WHERE persona='merchant' AND instance_slug='m-mfa-role'`)
	})

	defineGR := defineRoleGR("merchant")
	w := s.drive(t, defineGR, "m-mfa-role", owner, `{"role":"sensitive","permissions":["merchant:billing:read"],"requires_mfa":true}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	require.Equal(t, true, created["requires_mfa"])

	var subject string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(&subject))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id = $1::uuid`, subject) })

	// Not enrolled in 2FA yet: assignment must be refused (403, 2fa_enrollment_required).
	assignGR := memberRoleAssignGR("merchant")
	repl := strings.NewReplacer(":instance_slug", "m-mfa-role", ":user", subject, ":role", "sensitive")
	w = s.driveSub(t, assignGR, repl, owner)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "2fa_enrollment_required")

	// After enrolling, the SAME assignment succeeds.
	_, err = s.svc.Enable2FA(ctx, subject, "email", nil)
	require.NoError(t, err)
	w = s.driveSub(t, assignGR, repl, owner)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}
