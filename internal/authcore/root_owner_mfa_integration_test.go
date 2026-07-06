package authcore

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func cleanRootGroupTables(ctx context.Context, pool *pgxpool.Pool) {
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_remote_application_roles`)
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_user_roles`)
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups`)
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_persona_parents`)
}

// The root persona's injected owner role is MFA-required by default: assigning
// it is blocked until the subject has enabled 2FA.
func TestRootOwnerRequiresMFA_AssignmentBlockedThenAllowed_DB(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	cleanRootGroupTables(ctx, pool)
	t.Cleanup(func() { cleanRootGroupTables(ctx, pool) })

	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	if _, err := svc.EnsureRootGroup(ctx); err != nil {
		t.Fatalf("EnsureRootGroup: %v", err)
	}

	user := insertBareUser(t, pool)
	if err := svc.AssignGroupRole(ctx, RootPersona, "", user, SubjectKindUser, OwnerRoleName); !errors.Is(err, ErrTwoFAEnrollmentRequired) {
		t.Fatalf("assign root owner without MFA = %v, want ErrTwoFAEnrollmentRequired", err)
	}
	if _, err := svc.Enable2FA(ctx, user, "email", nil); err != nil {
		t.Fatalf("Enable2FA: %v", err)
	}
	if err := svc.AssignGroupRole(ctx, RootPersona, "", user, SubjectKindUser, OwnerRoleName); err != nil {
		t.Fatalf("assign root owner after MFA: %v", err)
	}
	if ok, err := svc.Can(ctx, user, SubjectKindUser, RootPersona, "", PermRootResourcesRead); err != nil || !ok {
		t.Fatalf("root owner should hold root:* after assignment; got %v,%v", ok, err)
	}
}

// A host that explicitly declares the root owner role with RequiresMFA: false
// overrides the default — assignment succeeds without any 2FA enrolled.
func TestRootOwnerRequiresMFA_ExplicitOverrideAllowsUnenrolledAssignment_DB(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	cleanRootGroupTables(ctx, pool)
	t.Cleanup(func() { cleanRootGroupTables(ctx, pool) })

	gs, err := NewGroupSchema(PersonaDef{
		Name: RootPersona,
		Roles: []RoleDef{
			{Name: OwnerRoleName, Permissions: []string{OwnerGrant(RootPersona)}, RequiresMFA: false},
		},
	})
	if err != nil {
		t.Fatalf("NewGroupSchema: %v", err)
	}
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	svc.groupSchema = gs
	if _, err := svc.EnsureRootGroup(ctx); err != nil {
		t.Fatalf("EnsureRootGroup: %v", err)
	}

	user := insertBareUser(t, pool)
	if err := svc.AssignGroupRole(ctx, RootPersona, "", user, SubjectKindUser, OwnerRoleName); err != nil {
		t.Fatalf("assign explicitly-non-MFA root owner without MFA = %v, want nil", err)
	}
}

// When the deployment has 2FA disabled (Mode == Disabled), the root owner's
// RequiresMFA default must be completely inert: bootstrap-seeding a root owner
// (CreatePermissionGroup with OwnerSubjectID, the genesis path) must not brick.
func TestRootOwnerRequiresMFA_InertWhenTwoFactorDisabled_DB(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	cleanRootGroupTables(ctx, pool)
	t.Cleanup(func() { cleanRootGroupTables(ctx, pool) })

	svc := NewService(Config{
		Token:     TokenConfig{Issuer: "https://test"},
		TwoFactor: TwoFactorConfig{Mode: TwoFactorDisabled},
	}, Keyset{}, WithPostgres(pool))

	user := insertBareUser(t, pool)
	if _, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: RootPersona, OwnerSubjectID: user}); err != nil {
		t.Fatalf("bootstrap-seed root owner with 2FA disabled = %v, want nil (must never brick)", err)
	}
	if ok, err := svc.Can(ctx, user, SubjectKindUser, RootPersona, "", PermRootResourcesRead); err != nil || !ok {
		t.Fatalf("seeded root owner should hold root:*; got %v,%v", ok, err)
	}

	// Also inert on the plain AssignGroupRole path for a second user.
	user2 := insertBareUser(t, pool)
	if err := svc.AssignGroupRole(ctx, RootPersona, "", user2, SubjectKindUser, OwnerRoleName); err != nil {
		t.Fatalf("assign root owner with 2FA disabled = %v, want nil", err)
	}
}

// The sole root owner disabling their own 2FA must be refused outright — never
// silently keep the role (2FA stays on) nor silently strip it (root group left
// ownerless). Once a second owner exists, the disable succeeds and only the
// disabling user's owner role is removed.
func TestSoleRootOwnerDisable2FA_Refused_DB(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	cleanRootGroupTables(ctx, pool)
	t.Cleanup(func() { cleanRootGroupTables(ctx, pool) })

	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	if _, err := svc.EnsureRootGroup(ctx); err != nil {
		t.Fatalf("EnsureRootGroup: %v", err)
	}

	owner1 := insertBareUser(t, pool)
	if _, err := svc.Enable2FA(ctx, owner1, "email", nil); err != nil {
		t.Fatalf("Enable2FA owner1: %v", err)
	}
	if err := svc.AssignGroupRole(ctx, RootPersona, "", owner1, SubjectKindUser, OwnerRoleName); err != nil {
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
	if ok, err := svc.Can(ctx, owner1, SubjectKindUser, RootPersona, "", PermRootResourcesRead); err != nil || !ok {
		t.Fatalf("sole owner must still hold root:* after a refused disable; got %v,%v", ok, err)
	}

	// Add a second owner; now owner1 can disable their own 2FA (only their
	// owner role is stripped, owner2 is unaffected).
	owner2 := insertBareUser(t, pool)
	if _, err := svc.Enable2FA(ctx, owner2, "email", nil); err != nil {
		t.Fatalf("Enable2FA owner2: %v", err)
	}
	if err := svc.AssignGroupRole(ctx, RootPersona, "", owner2, SubjectKindUser, OwnerRoleName); err != nil {
		t.Fatalf("assign owner2: %v", err)
	}

	removed, err := svc.Disable2FAWithRemovedRoles(ctx, owner1)
	if err != nil {
		t.Fatalf("Disable2FAWithRemovedRoles owner1 (non-sole): %v", err)
	}
	if len(removed) != 1 || removed[0].Role != OwnerRoleName {
		t.Fatalf("removed = %+v, want only the owner role", removed)
	}
	if ok, _ := svc.Can(ctx, owner1, SubjectKindUser, RootPersona, "", PermRootResourcesRead); ok {
		t.Fatalf("owner1 should have lost root:* after disabling 2FA")
	}
	if ok, err := svc.Can(ctx, owner2, SubjectKindUser, RootPersona, "", PermRootResourcesRead); err != nil || !ok {
		t.Fatalf("owner2 should be unaffected; got %v,%v", ok, err)
	}
}

// removeMFARequiredUserRoles (a USER's own decision to disable their 2FA) is
// NOT gated by the app's TwoFactor Mode — unlike role assignment, which the
// host's Mode gates. Application-mode toggles must never themselves mutate
// role/2FA state; here it is the user's own action that triggers the strip,
// so it applies regardless of the app's current enforcement mode.
func TestDisable2FAStripsMFARoles_IndependentOfTwoFactorMode_DB(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	cleanRootGroupTables(ctx, pool)
	t.Cleanup(func() { cleanRootGroupTables(ctx, pool) })

	gs, err := BuildSchema(PersonaDef{
		Name: "org", Parent: RootPersona,
		Roles: []RoleDef{{Name: "member", Permissions: []string{"org:repo:read"}, RequiresMFA: true}},
	})
	if err != nil {
		t.Fatalf("BuildSchema: %v", err)
	}

	// Enrolled + assigned while 2FA is enabled (Mode defaults to Optional).
	enabled := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	enabled.groupSchema = gs
	if err := enabled.SeedPermissionGroupContainment(ctx); err != nil {
		t.Fatalf("SeedPermissionGroupContainment: %v", err)
	}
	if _, err := enabled.EnsureRootGroup(ctx); err != nil {
		t.Fatalf("EnsureRootGroup: %v", err)
	}
	user := insertBareUser(t, pool)
	if _, err := enabled.Enable2FA(ctx, user, "email", nil); err != nil {
		t.Fatalf("Enable2FA: %v", err)
	}
	if _, err := enabled.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "org", InstanceSlug: "acme"}); err != nil {
		t.Fatalf("CreatePermissionGroup: %v", err)
	}
	if err := enabled.AssignGroupRole(ctx, "org", "acme", user, SubjectKindUser, "member"); err != nil {
		t.Fatalf("assign member: %v", err)
	}

	// The host later flips TwoFactor.Mode to Disabled (a fresh Service sharing
	// the same DB state models a config-only redeploy). The user then disables
	// their own 2FA: the strip still fires — it is not gated by app Mode.
	disabled := NewService(Config{
		Token:     TokenConfig{Issuer: "https://test"},
		TwoFactor: TwoFactorConfig{Mode: TwoFactorDisabled},
	}, Keyset{}, WithPostgres(pool))
	disabled.groupSchema = gs

	removed, err := disabled.Disable2FAWithRemovedRoles(ctx, user)
	if err != nil {
		t.Fatalf("Disable2FAWithRemovedRoles while Mode=Disabled: %v", err)
	}
	if len(removed) != 1 || removed[0].Role != "member" {
		t.Fatalf("removed = %+v, want only member", removed)
	}
	if ok, _ := disabled.Can(ctx, user, SubjectKindUser, "org", "acme", "org:repo:read"); ok {
		t.Fatalf("member role should be stripped even with 2FA Mode disabled")
	}
}
