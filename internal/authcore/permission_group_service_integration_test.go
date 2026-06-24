package authcore

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
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_persona_parents`)
	}
	clean()
	t.Cleanup(clean)

	gs, err := BuildSchema(
		PersonaDef{
			Name: "org", AllowedParents: []string{RootPersona}, AllowCustomRoles: true,
			Routes: ManagementProfile{MemberAssignment: true, CustomRoleCreation: true},
			Roles:  []RoleDef{{Name: "member", Permissions: []string{"org:repo:read"}}},
		},
		PersonaDef{
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
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id = ANY($1::uuid[])`, []string{owner, dev})
	})

	// Create an org persona group (owner seeded) under root; then a repo under it.
	if _, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "org", InstanceSlug: "acme", OwnerSubjectID: owner}); err != nil {
		t.Fatalf("create org permission group: %v", err)
	}
	if _, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "repo", InstanceSlug: "r1", ParentInstanceSlug: "acme"}); err != nil {
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
	if err := svc.AssignGroupRole(ctx, "repo", "r1", dev, SubjectKindUser, MemberRoleName); err != nil {
		t.Fatalf("replace writer with member: %v", err)
	}
	if ok, _ := svc.Can(ctx, dev, SubjectKindUser, "repo", "r1", "repo:repo:write"); ok {
		t.Errorf("replacing a member's role should remove the previous writer grant")
	}

	// Read surface: list a group's members + a subject's groups.
	members, err := svc.ListGroupMembers(ctx, "org", "acme")
	if err != nil {
		t.Fatalf("ListGroupMembers: %v", err)
	}
	foundOwner := false
	for _, m := range members {
		if m.SubjectID == owner && m.Role == OwnerRoleName {
			foundOwner = true
		}
	}
	if !foundOwner {
		t.Errorf("ListGroupMembers(org,acme) should include the owner; got %+v", members)
	}
	sgroups, err := svc.ListSubjectGroups(ctx, dev, SubjectKindUser)
	if err != nil {
		t.Fatalf("ListSubjectGroups: %v", err)
	}
	if len(sgroups) == 0 || sgroups[0].Persona != "repo" || sgroups[0].InstanceSlug != "r1" {
		t.Errorf("ListSubjectGroups(dev) should show the repo:r1 membership; got %+v", sgroups)
	}
	if len(sgroups) != 1 || sgroups[0].Role != MemberRoleName {
		t.Errorf("ListSubjectGroups(dev) should show one current role after replacement; got %+v", sgroups)
	}

	// Role validation: repo disallows custom roles, so an unknown role is rejected.
	if err := svc.AssignGroupRole(ctx, "repo", "r1", dev, SubjectKindUser, "nonsense"); err == nil {
		t.Errorf("unknown role on a fixed-catalog persona should be rejected")
	}

	// Containment enforced at the service layer (before the DB): repo under root.
	if _, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "repo", InstanceSlug: "rX", ParentPersona: RootPersona}); err == nil {
		t.Errorf("repo directly under root should be rejected")
	}
}

// TestService_CustomRoleDefineDelete exercises the custom-role define/delete path
// (the last-wired generated-route family) end-to-end against a real Postgres.
func TestService_CustomRoleDefineDelete(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	clean := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_persona_parents`)
	}
	clean()
	t.Cleanup(clean)

	gs, err := BuildSchema(PersonaDef{
		Name: "org", AllowedParents: []string{RootPersona}, AllowCustomRoles: true,
		Routes: ManagementProfile{MemberAssignment: true, CustomRoleCreation: true},
	})
	if err != nil {
		t.Fatalf("BuildSchema: %v", err)
	}
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool))
	svc.groupSchema = gs
	if err := svc.SeedPermissionGroupContainment(ctx); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := svc.EnsureRootGroup(ctx); err != nil {
		t.Fatalf("root: %v", err)
	}
	if _, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "org", InstanceSlug: "acme"}); err != nil {
		t.Fatalf("create org permission group: %v", err)
	}
	var uid string
	if err := pool.QueryRow(ctx, `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(&uid); err != nil {
		t.Fatalf("user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id = $1`, uid) })

	// define a custom role, assign it to a non-owner, authorize.
	if err := svc.DefineGroupCustomRole(ctx, "org", "acme", "auditor", []string{"org:billing:read"}); err != nil {
		t.Fatalf("DefineGroupCustomRole: %v", err)
	}
	if err := svc.AssignGroupRole(ctx, "org", "acme", uid, SubjectKindUser, "auditor"); err != nil {
		t.Fatalf("assign auditor: %v", err)
	}
	if ok, err := svc.Can(ctx, uid, SubjectKindUser, "org", "acme", "org:billing:read"); err != nil || !ok {
		t.Errorf("custom auditor role should grant org:billing:read; got %v,%v", ok, err)
	}
	if err := svc.RemoveGroupSubject(ctx, "org", "acme", uid, SubjectKindUser); err != nil {
		t.Fatalf("RemoveGroupSubject: %v", err)
	}
	if ok, _ := svc.Can(ctx, uid, SubjectKindUser, "org", "acme", "org:billing:read"); ok {
		t.Errorf("removing a member should revoke custom-role grants too")
	}
	if err := svc.AssignGroupRole(ctx, "org", "acme", uid, SubjectKindUser, "auditor"); err != nil {
		t.Fatalf("reassign auditor: %v", err)
	}
	// cross-persona custom perm is rejected (namespace purity).
	if err := svc.DefineGroupCustomRole(ctx, "org", "acme", "bad", []string{"repo:repo:read"}); err == nil {
		t.Errorf("a cross-persona custom-role grant must be rejected")
	}
	// delete -> the grant is gone.
	if err := svc.DeleteGroupCustomRole(ctx, "org", "acme", "auditor"); err != nil {
		t.Fatalf("DeleteGroupCustomRole: %v", err)
	}
	if ok, _ := svc.Can(ctx, uid, SubjectKindUser, "org", "acme", "org:billing:read"); ok {
		t.Errorf("after delete, the custom-role grant must be gone")
	}
}
