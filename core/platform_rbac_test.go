package core

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestPlatformRBAC exercises Layer-2 platform RBAC (#95): role definition +
// perms, direct assignment, effective resolution (incl. super-admin `platform:*`
// expansion and the regular-user short-circuit), the DISJOINT-namespace rule in
// BOTH directions, and no-escalation. Skips without AUTHKIT_TEST_DATABASE_URL.
func TestPlatformRBAC(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	has := func(xs []string, x string) bool {
		for _, v := range xs {
			if v == x {
				return true
			}
		}
		return false
	}
	suffix := time.Now().UnixNano()
	mkUser := func(tag string) *User {
		u, err := svc.CreateUser(ctx, fmt.Sprintf("%s-%d@test.example", tag, suffix), fmt.Sprintf("%s%d", tag, suffix))
		if err != nil {
			t.Fatalf("create user %s: %v", tag, err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1`, u.ID) })
		return u
	}

	// --- scoped role: users:read + users:ban ---
	role := fmt.Sprintf("ops-admin-%d", suffix)
	t.Cleanup(func() { _, _ = svc.DeletePlatformRole(ctx, role) })
	if err := svc.DefinePlatformRole(ctx, role); err != nil {
		t.Fatalf("define platform role: %v", err)
	}
	if err := svc.SetPlatformRolePermissions(ctx, role, []string{PermPlatformUsersRead, PermPlatformUsersBan}); err != nil {
		t.Fatalf("set platform role perms: %v", err)
	}

	admin := mkUser("platadmin")
	if err := svc.AssignPlatformRole(ctx, admin.ID, role); err != nil {
		t.Fatalf("assign platform role: %v", err)
	}
	eff, err := svc.EffectivePlatformPermissions(ctx, admin.ID)
	if err != nil {
		t.Fatalf("effective platform perms: %v", err)
	}
	if !has(eff, PermPlatformUsersRead) || !has(eff, PermPlatformUsersBan) {
		t.Fatalf("admin should hold users:read+ban, got %v", eff)
	}
	if has(eff, PermPlatformUsersDelete) {
		t.Fatalf("admin must NOT hold users:delete, got %v", eff)
	}
	ok, err := svc.HasPlatformPermission(ctx, admin.ID, PermPlatformUsersBan)
	if err != nil || !ok {
		t.Fatalf("HasPlatformPermission users:ban=(%v,%v), want true,nil", ok, err)
	}
	ok, err = svc.HasPlatformPermission(ctx, admin.ID, PermPlatformUsersDelete)
	if err != nil || ok {
		t.Fatalf("HasPlatformPermission users:delete=(%v,%v), want false,nil", ok, err)
	}

	// --- super-admin: platform:* expands to the whole platform catalog ---
	super := fmt.Sprintf("super-%d", suffix)
	t.Cleanup(func() { _, _ = svc.DeletePlatformRole(ctx, super) })
	if err := svc.DefinePlatformRole(ctx, super); err != nil {
		t.Fatalf("define super role: %v", err)
	}
	if err := svc.SetPlatformRolePermissions(ctx, super, []string{PlatformSuperAdminGrant}); err != nil {
		t.Fatalf("set super perms: %v", err)
	}
	superUser := mkUser("super")
	if err := svc.AssignPlatformRole(ctx, superUser.ID, super); err != nil {
		t.Fatalf("assign super: %v", err)
	}
	superEff, err := svc.EffectivePlatformPermissions(ctx, superUser.ID)
	if err != nil {
		t.Fatalf("super eff: %v", err)
	}
	for _, d := range BasePlatformPermissions() {
		if !has(superEff, d.Name) {
			t.Fatalf("super-admin (platform:*) should confer %s, got %v", d.Name, superEff)
		}
	}
	ok, err = svc.HasPlatformPermission(ctx, superUser.ID, PermPlatformOrgsRecover)
	if err != nil || !ok {
		t.Fatalf("HasPlatformPermission platform:* recover=(%v,%v), want true,nil", ok, err)
	}

	// --- regular user (no platform roles) → zero platform authority (short-circuit) ---
	plain := mkUser("plain")
	plainEff, err := svc.EffectivePlatformPermissions(ctx, plain.ID)
	if err != nil {
		t.Fatalf("plain eff: %v", err)
	}
	if len(plainEff) != 0 {
		t.Fatalf("regular user must have zero platform perms, got %v", plainEff)
	}
	ok, err = svc.HasPlatformPermission(ctx, plain.ID, PermPlatformUsersRead)
	if err != nil || ok {
		t.Fatalf("plain HasPlatformPermission=(%v,%v), want false,nil", ok, err)
	}

	// --- DISJOINT: a platform role REJECTS org:/bare-*/negation/unknown ---
	unknown, _, err := svc.ValidatePlatformGrant(ctx, "", []string{"org:members:read", "*", "!platform:users:ban", "platform:bogus:thing"}, true)
	if err != nil {
		t.Fatalf("validate platform grant: %v", err)
	}
	if len(unknown) != 4 {
		t.Fatalf("expected 4 disallowed tokens flagged unknown, got %v", unknown)
	}
	if u2, _, _ := svc.ValidatePlatformGrant(ctx, "", []string{PermPlatformUsersRead, PlatformSuperAdminGrant}, true); len(u2) != 0 {
		t.Fatalf("legit platform tokens should validate clean, got unknown=%v", u2)
	}

	// --- no-escalation: actor with users:read+ban cannot grant users:delete ---
	_, offending, err := svc.ValidatePlatformGrant(ctx, admin.ID, []string{PermPlatformUsersDelete}, false)
	if err != nil {
		t.Fatalf("validate no-escalation: %v", err)
	}
	if len(offending) != 1 {
		t.Fatalf("actor lacking users:delete must not grant it, offending=%v", offending)
	}
	if _, off2, _ := svc.ValidatePlatformGrant(ctx, admin.ID, []string{PermPlatformUsersRead}, false); len(off2) != 0 {
		t.Fatalf("actor should grant a perm they hold, offending=%v", off2)
	}

	// --- DISJOINT (reverse): an ORG role REJECTS a platform: perm ---
	orgSlug := fmt.Sprintf("disjoint-org-%d", suffix)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, orgSlug) })
	if _, err := svc.CreateOrg(ctx, orgSlug); err != nil {
		t.Fatalf("create org: %v", err)
	}
	ou, _, err := svc.ValidateGrant(ctx, orgSlug, "", []string{PermPlatformUsersBan}, true)
	if err != nil {
		t.Fatalf("org validate: %v", err)
	}
	if len(ou) != 1 {
		t.Fatalf("org role must reject a platform: perm (disjoint), unknown=%v", ou)
	}
}
