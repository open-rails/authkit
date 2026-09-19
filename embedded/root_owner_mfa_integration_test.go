package embedded

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
)

func cleanRootGroupTables(ctx context.Context, pool *pgxpool.Pool) {
	_, _ = pool.Exec(ctx, `DELETE FROM group_remote_application_roles`)
	_, _ = pool.Exec(ctx, `DELETE FROM group_user_roles`)
	_, _ = pool.Exec(ctx, `DELETE FROM permission_groups`)
	_, _ = pool.Exec(ctx, `DELETE FROM group_persona_parents`)
}

// The sole root owner disabling their own 2FA must be refused outright — never
// silently keep the role (2FA stays on) nor silently strip it (root group left
// ownerless). Once a second owner exists, the disable succeeds and only the
// disabling user's owner role is removed.
func TestSoleRootOwnerDisable2FA_Refused_DB(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	cleanRootGroupTables(ctx, pool)
	t.Cleanup(func() { cleanRootGroupTables(ctx, pool) })

	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	if _, err := svc.EnsureRootGroup(ctx); err != nil {
		t.Fatalf("EnsureRootGroup: %v", err)
	}

	owner1 := insertBareUser(t, pool)
	if _, err := svc.Enable2FA(ctx, owner1, "email", nil, AllowAdditionalFactors); err != nil {
		t.Fatalf("Enable2FA owner1: %v", err)
	}
	if err := svc.AssignGroupRole(ctx, authkit.RootGroup(), authkit.UserSubject(owner1), OwnerRoleName); err != nil {
		t.Fatalf("assign owner1: %v", err)
	}

	// Sole owner: disabling 2FA must be refused, not silently applied.
	if _, err := svc.Disable2FAWithRemovedRoles(ctx, owner1); !errors.Is(err, ErrCannotRemoveLastAdminRole) {
		t.Fatalf("sole root owner Disable2FA = %v, want ErrCannotRemoveLastAdminRole", err)
	}
	status, err := svc.MFAStatus(ctx, owner1)
	if err != nil || !status.Enabled {
		t.Fatalf("sole owner's 2FA must remain enabled after a refused disable; status=%+v err=%v", status, err)
	}
	if ok, err := svc.Can(ctx, authkit.UserSubject(owner1), authkit.RootGroup(), PermRootResourcesRead); err != nil || !ok {
		t.Fatalf("sole owner must still hold root:* after a refused disable; got %v,%v", ok, err)
	}

	// Add a second owner; now owner1 can disable their own 2FA (only their
	// owner role is stripped, owner2 is unaffected).
	owner2 := insertBareUser(t, pool)
	if _, err := svc.Enable2FA(ctx, owner2, "email", nil, AllowAdditionalFactors); err != nil {
		t.Fatalf("Enable2FA owner2: %v", err)
	}
	if err := svc.AssignGroupRole(ctx, authkit.RootGroup(), authkit.UserSubject(owner2), OwnerRoleName); err != nil {
		t.Fatalf("assign owner2: %v", err)
	}

	removed, err := svc.Disable2FAWithRemovedRoles(ctx, owner1)
	if err != nil {
		t.Fatalf("Disable2FAWithRemovedRoles owner1 (non-sole): %v", err)
	}
	if len(removed) != 1 || removed[0].Role != OwnerRoleName {
		t.Fatalf("removed = %+v, want only the owner role", removed)
	}
	if ok, _ := svc.Can(ctx, authkit.UserSubject(owner1), authkit.RootGroup(), PermRootResourcesRead); ok {
		t.Fatalf("owner1 should have lost root:* after disabling 2FA")
	}
	if ok, err := svc.Can(ctx, authkit.UserSubject(owner2), authkit.RootGroup(), PermRootResourcesRead); err != nil || !ok {
		t.Fatalf("owner2 should be unaffected; got %v,%v", ok, err)
	}
}
