package authcore

import (
	"context"
	"errors"
	"testing"
)

// #249 follow-up: an MFA-required role can be assigned while TwoFactor.Mode is
// Disabled — requireMFAForRoleAssignment short-circuits there so bootstrap
// can't brick itself. If the host later re-enables 2FA (Mode: Optional), that
// role holder now sits with an MFA-required role and no enrollment, and the
// ONLY prior session-time gate (requireMFAEnrollment) is tied to
// Mode==Required for EVERY user — it never looked at per-role holders under
// Optional. This proves requireSessionMFAStateWith now closes that gap at
// login (IssueAuthenticatedSession/IssueRefreshSession) and refresh
// (ExchangeRefreshToken), without gating anyone else, and that Mode=Disabled
// stays completely gate-free throughout.
func TestMFARequiredRoleLoginGate_DB(t *testing.T) {
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

	// Bootstrap era: 2FA fully disabled. The assignment gate is inert, so the
	// MFA-required "member" role can be handed to a user who has never
	// enrolled — exactly the genesis/short-circuit this edge protects.
	disabled := NewService(Config{
		Token:     TokenConfig{Issuer: "https://test"},
		TwoFactor: TwoFactorConfig{Mode: TwoFactorDisabled},
	}, Keyset{}, WithPostgres(pool))
	disabled.groupSchema = gs
	if err := disabled.SeedPermissionGroupContainment(ctx); err != nil {
		t.Fatalf("SeedPermissionGroupContainment: %v", err)
	}
	if _, err := disabled.EnsureRootGroup(ctx); err != nil {
		t.Fatalf("EnsureRootGroup: %v", err)
	}
	if _, err := disabled.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "org", InstanceSlug: "acme"}); err != nil {
		t.Fatalf("CreatePermissionGroup: %v", err)
	}

	unenrolledHolder := insertBareUser(t, pool)
	if err := disabled.AssignGroupRole(ctx, "org", "acme", unenrolledHolder, SubjectKindUser, "member"); err != nil {
		t.Fatalf("assign member while Mode=Disabled = %v, want nil (bootstrap must never brick)", err)
	}

	enrolledHolder := insertBareUser(t, pool)
	if err := disabled.AssignGroupRole(ctx, "org", "acme", enrolledHolder, SubjectKindUser, "member"); err != nil {
		t.Fatalf("assign member (enrolled-to-be) while Mode=Disabled: %v", err)
	}
	if _, err := disabled.Enable2FA(ctx, enrolledHolder, "email", nil); err != nil {
		t.Fatalf("Enable2FA enrolledHolder: %v", err)
	}

	roleLess := insertBareUser(t, pool)

	// Mode=Disabled stays gate-free for everyone, including the unenrolled
	// role holder: enforcement toggles never mutate roles/2FA state, so
	// flipping Mode back on later must find things exactly as bootstrap left
	// them.
	if _, _, _, err := disabled.IssueRefreshSession(ctx, unenrolledHolder, "test", nil); err != nil {
		t.Fatalf("Mode=Disabled must stay gate-free for the unenrolled role holder: %v", err)
	}

	// Mint a refresh token for the unenrolled holder now, while still
	// Mode=Disabled — modeling a session that already existed before the host
	// re-enables 2FA.
	_, preFlipRefreshTok, _, err := disabled.IssueRefreshSession(ctx, unenrolledHolder, "test", nil)
	if err != nil {
		t.Fatalf("mint refresh token while Mode=Disabled: %v", err)
	}

	// The host re-enables 2FA (Mode: Optional). Mode is read fresh on every
	// call, so a second Service sharing the same DB state models exactly a
	// config-only redeploy — nothing above was mutated by the flip.
	optional := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	optional.groupSchema = gs

	// 1. LOGIN: the unenrolled MFA-required-role holder is now challenged to
	// enroll instead of being let through.
	if _, _, _, err := optional.IssueRefreshSession(ctx, unenrolledHolder, "test", nil); !errors.Is(err, ErrTwoFAEnrollmentRequired) {
		t.Fatalf("unenrolled MFA-required-role holder under Mode=Optional = %v, want ErrTwoFAEnrollmentRequired", err)
	}
	if _, _, _, _, _, err := optional.IssueAuthenticatedSession(ctx, unenrolledHolder, "test", nil, []string{"pwd"}, nil); !errors.Is(err, ErrTwoFAEnrollmentRequired) {
		t.Fatalf("IssueAuthenticatedSession for unenrolled MFA-required-role holder = %v, want ErrTwoFAEnrollmentRequired", err)
	}

	// 2. An already-enrolled holder is unaffected.
	if _, _, _, err := optional.IssueRefreshSessionWithAuthMethods(ctx, enrolledHolder, "test", nil, []string{"pwd", "otp", "mfa"}); err != nil {
		t.Fatalf("enrolled MFA-required-role holder should be unaffected: %v", err)
	}

	// 3. A role-less unenrolled user is unaffected.
	if _, _, _, err := optional.IssueRefreshSession(ctx, roleLess, "test", nil); err != nil {
		t.Fatalf("role-less unenrolled user should be unaffected: %v", err)
	}

	// 4. REFRESH: exchanging the pre-flip refresh token now (Mode=Optional)
	// is denied with the wrapped enrollment-required error the refresh
	// handler knows how to turn into a usable enrollment token (#148).
	if _, _, _, err := optional.ExchangeRefreshToken(ctx, preFlipRefreshTok, "test", nil); err == nil {
		t.Fatalf("refresh for unenrolled MFA-required-role holder under Mode=Optional should be denied")
	} else {
		var ee *TwoFAEnrollmentRequiredError
		if !errors.As(err, &ee) || ee.UserID != unenrolledHolder {
			t.Fatalf("ExchangeRefreshToken err = %v, want *TwoFAEnrollmentRequiredError{UserID: %s}", err, unenrolledHolder)
		}
	}
}
