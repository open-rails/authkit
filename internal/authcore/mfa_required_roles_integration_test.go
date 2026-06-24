package authcore

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMFARequiredRoleAssignmentAndDisableLifecycle(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	clean := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_remote_application_roles`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_user_roles`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_persona_parents`)
	}
	clean()
	t.Cleanup(clean)

	gs, err := BuildSchema(
		IntrinsicRootPersona(RoleDef{Name: "admin", Permissions: []string{PermRootResourcesRead}, RequiresMFA: true}),
		PersonaDef{
			Name: "org", AllowedParents: []string{RootPersona},
			Routes: ManagementProfile{MemberAssignment: true},
			Roles:  []RoleDef{{Name: "member", Permissions: []string{"org:repo:read"}}},
		},
	)
	if err != nil {
		t.Fatalf("BuildSchema: %v", err)
	}
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool))
	svc.groupSchema = gs
	if err := svc.SeedPermissionGroupContainment(ctx); err != nil {
		t.Fatalf("SeedPermissionGroupContainment: %v", err)
	}
	if _, err := svc.EnsureRootGroup(ctx); err != nil {
		t.Fatalf("EnsureRootGroup: %v", err)
	}

	userID := insertBareUser(t, pool)
	if err := svc.AssignGroupRole(ctx, RootPersona, "", userID, SubjectKindUser, "admin"); !errors.Is(err, ErrTwoFAEnrollmentRequired) {
		t.Fatalf("assign MFA-required role without MFA = %v", err)
	}
	if _, err := svc.Enable2FA(ctx, userID, "email", nil); err != nil {
		t.Fatalf("Enable2FA: %v", err)
	}
	if err := svc.AssignGroupRole(ctx, RootPersona, "", userID, SubjectKindUser, "admin"); err != nil {
		t.Fatalf("assign admin after MFA: %v", err)
	}
	if _, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "org", InstanceSlug: "acme"}); err != nil {
		t.Fatalf("CreatePermissionGroup: %v", err)
	}
	if err := svc.AssignGroupRole(ctx, "org", "acme", userID, SubjectKindUser, "member"); err != nil {
		t.Fatalf("assign member: %v", err)
	}

	removed, err := svc.Disable2FAWithRemovedRoles(ctx, userID)
	if err != nil {
		t.Fatalf("Disable2FAWithRemovedRoles: %v", err)
	}
	if len(removed) != 1 || removed[0].Role != "admin" {
		t.Fatalf("removed = %+v, want only admin", removed)
	}
	if ok, _ := svc.Can(ctx, userID, SubjectKindUser, RootPersona, "", PermRootResourcesRead); ok {
		t.Fatalf("admin role should be removed after disabling MFA")
	}
	if ok, _ := svc.Can(ctx, userID, SubjectKindUser, "org", "acme", "org:repo:read"); !ok {
		t.Fatalf("ordinary org persona role should remain after disabling MFA")
	}
}

func TestMFARequiredInviteAcceptLifecycle(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	clean := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_invites`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_remote_application_roles`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_user_roles`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_persona_parents`)
	}
	clean()
	t.Cleanup(clean)

	gs, err := BuildSchema(PersonaDef{
		Name: "org", AllowedParents: []string{RootPersona},
		Routes: ManagementProfile{MemberAssignment: true, InviteLinks: true},
		Roles:  []RoleDef{{Name: "member", Permissions: []string{"org:repo:read"}, RequiresMFA: true}},
	})
	if err != nil {
		t.Fatalf("BuildSchema: %v", err)
	}
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool))
	svc.groupSchema = gs
	if err := svc.SeedPermissionGroupContainment(ctx); err != nil {
		t.Fatalf("SeedPermissionGroupContainment: %v", err)
	}
	if _, err := svc.EnsureRootGroup(ctx); err != nil {
		t.Fatalf("EnsureRootGroup: %v", err)
	}

	owner := insertBareUser(t, pool)
	invitee := insertBareUser(t, pool)
	if _, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "org", InstanceSlug: "acme", OwnerSubjectID: owner}); err != nil {
		t.Fatalf("CreatePermissionGroup: %v", err)
	}
	// AssignGroupRole enforces the same MFA-on-assignment guard the old invite
	// accept did (requireMFAForRoleAssignment): an MFA-required role cannot be
	// granted to a user without enabled MFA.
	if err := svc.AssignGroupRole(ctx, "org", "acme", invitee, SubjectKindUser, "member"); !errors.Is(err, ErrTwoFAEnrollmentRequired) {
		t.Fatalf("assign MFA-required role without MFA = %v", err)
	}
	if _, err := svc.Enable2FA(ctx, invitee, "email", nil); err != nil {
		t.Fatalf("Enable2FA: %v", err)
	}
	if err := svc.AssignGroupRole(ctx, "org", "acme", invitee, SubjectKindUser, "member"); err != nil {
		t.Fatalf("assign after MFA: %v", err)
	}
	if ok, err := svc.Can(ctx, invitee, SubjectKindUser, "org", "acme", "org:repo:read"); err != nil || !ok {
		t.Fatalf("invitee should hold org:repo:read after accept; got %v,%v", ok, err)
	}
}

func insertBareUser(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(&id); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.users WHERE id=$1::uuid`, id)
	})
	return id
}

// RequireMFAEnrollment is the global "force 2FA at signup / first session" policy:
// a user without usable 2FA cannot establish or refresh a session until they enroll,
// independent of any per-role RequiresMFA.
func TestRequireMFAEnrollmentForcesEnrollment(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	user := insertBareUser(t, pool)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.refresh_sessions WHERE user_id=$1::uuid`, user) })

	// Default policy: a user without 2FA can establish a session.
	lenient := NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool))
	if _, _, _, err := lenient.IssueRefreshSession(ctx, user, "test", nil); err != nil {
		t.Fatalf("default policy should allow a no-2FA session: %v", err)
	}

	// RequireMFAEnrollment: the same user is blocked until they enroll 2FA.
	strict := NewService(Options{Issuer: "https://test", RequireMFAEnrollment: true}, Keyset{}, WithPostgres(pool))
	if _, _, _, err := strict.IssueRefreshSession(ctx, user, "test", nil); !errors.Is(err, ErrTwoFAEnrollmentRequired) {
		t.Fatalf("RequireMFAEnrollment without 2FA = %v, want ErrTwoFAEnrollmentRequired", err)
	}

	// After enrolling a usable factor and authenticating with 2FA, sessions resume.
	phone := "+15555550142"
	if _, err := strict.Enable2FA(ctx, user, "sms", &phone); err != nil {
		t.Fatalf("Enable2FA: %v", err)
	}
	if _, _, _, err := strict.IssueRefreshSessionWithAuthMethods(ctx, user, "test", nil, []string{"pwd", "otp", "mfa"}); err != nil {
		t.Fatalf("enrolled user with a 2FA session should be allowed: %v", err)
	}
}
