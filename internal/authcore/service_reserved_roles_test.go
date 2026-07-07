package authcore

import (
	"context"
	"testing"
)

func TestAssignRoleBySlug_AllowsOwnerGenesis(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))

	var userID string
	if err := pool.QueryRow(ctx, `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, userID) })

	// The genesis slug path skips the owner-reserved guard (#136) but NOT the
	// MFA-enrollment gate — the root owner requires MFA by default, so enroll.
	if _, err := svc.Enable2FA(ctx, userID, "email", nil); err != nil {
		t.Fatalf("enroll 2FA: %v", err)
	}

	if err := svc.AssignRoleBySlug(ctx, userID, OwnerRoleName); err != nil {
		t.Fatalf("assign owner through genesis helper: %v", err)
	}
	rolesByUser, err := svc.RoleSlugsByUsers(ctx, []string{userID})
	roles := rolesByUser[userID]
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	if !containsString(roles, OwnerRoleName) {
		t.Fatalf("roles=%v, want %q", roles, OwnerRoleName)
	}
}
