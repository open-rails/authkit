package core

import (
	"context"
	"testing"
)

// TestService_PermissionGroupLifecycle drives the public Service API end-to-end
// against a real Postgres (skips without AUTHKIT_TEST_DATABASE_URL, DB migrated
// through 008). The service methods commit their own transactions, so the test
// wipes the permission-group tables before/after (disposable test DB).
func TestService_PermissionGroupLifecycle(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	clean := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_type_parents`)
	}
	clean()
	t.Cleanup(clean)

	gs, err := BuildSchema(
		GroupTypeDef{
			Name: "org", AllowedParents: []string{RootType}, AllowCustomRoles: true,
			Routes: ManagementProfile{MemberAssignment: true, CustomRoleCreation: true},
			Roles:  []RoleDef{{Name: "member", Permissions: []string{"org:repo:read"}}},
		},
		GroupTypeDef{
			Name: "repo", AllowedParents: []string{"org"},
			Routes: ManagementProfile{MemberAssignment: true},
			Roles:  []RoleDef{{Name: "writer", Permissions: []string{"repo:repo:read", "repo:repo:write"}}},
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

	var owner, dev string
	for _, p := range []*string{&owner, &dev} {
		if err := pool.QueryRow(ctx, `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(p); err != nil {
			t.Fatalf("create user: %v", err)
		}
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id = ANY($1::uuid[])`, []string{owner, dev}) })

	// Create org (owner seeded) under root; then a repo under the org.
	if _, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Type: "org", ResourceRef: "acme", OwnerSubjectID: owner}); err != nil {
		t.Fatalf("create org: %v", err)
	}
	if _, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Type: "repo", ResourceRef: "r1", ParentResourceRef: "acme"}); err != nil {
		t.Fatalf("create repo: %v", err)
	}

	// Owner authorizes org:repo:read on the repo via walk-up; never repo:repo:write.
	if ok, err := svc.Can(ctx, owner, SubjectKindUser, "repo", "r1", "org:repo:read"); err != nil || !ok {
		t.Errorf("owner org:repo:read = %v,%v; want true", ok, err)
	}
	if ok, _ := svc.Can(ctx, owner, SubjectKindUser, "repo", "r1", "repo:repo:write"); ok {
		t.Errorf("owner must NOT hold repo:repo:write (namespace purity)")
	}

	// A per-repo collaborator: no authority until assigned, then repo-scoped only.
	if ok, _ := svc.Can(ctx, dev, SubjectKindUser, "repo", "r1", "repo:repo:write"); ok {
		t.Errorf("dev has no authority before assignment")
	}
	if err := svc.AssignGroupRole(ctx, "repo", "r1", dev, SubjectKindUser, "writer"); err != nil {
		t.Fatalf("assign writer: %v", err)
	}
	if ok, err := svc.Can(ctx, dev, SubjectKindUser, "repo", "r1", "repo:repo:write"); err != nil || !ok {
		t.Errorf("dev writer should hold repo:repo:write; got %v,%v", ok, err)
	}
	if ok, _ := svc.Can(ctx, dev, SubjectKindUser, "org", "acme", "org:repo:read"); ok {
		t.Errorf("a repo collaborator must NOT gain org-scoped authority")
	}

	// Role validation: repo disallows custom roles, so an unknown role is rejected.
	if err := svc.AssignGroupRole(ctx, "repo", "r1", dev, SubjectKindUser, "nonsense"); err == nil {
		t.Errorf("unknown role on a fixed-catalog type should be rejected")
	}

	// Containment enforced at the service layer (before the DB): repo under root.
	if _, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Type: "repo", ResourceRef: "rX", ParentType: RootType}); err == nil {
		t.Errorf("repo directly under root should be rejected")
	}
}
