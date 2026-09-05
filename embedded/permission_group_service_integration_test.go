package embedded

import (
	"context"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
)

// TestService_PermissionGroupLifecycle drives the public Client API end-to-end
// against a real Postgres (skips without AUTHKIT_TEST_DATABASE_URL, DB migrated
// through 008). The service methods commit their own transactions, so the test
// wipes the permission-group tables before/after (disposable test DB).
func TestService_PermissionGroupLifecycle(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	clean := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_persona_parents`)
	}
	clean()
	t.Cleanup(clean)

	gs, err := BuildSchema(
		PersonaDef{
			Name:         "org",
			Parent:       RootPersona,
			Capabilities: PersonaCapabilities{CustomRoles: true},
			Roles:        []RoleDef{{Name: "member", Permissions: []string{"org:repo:read"}}},
		},
		PersonaDef{
			Name: "repo", Parent: "org",
			Roles: []RoleDef{{Name: "writer", Permissions: []string{"repo:repo:read", "repo:repo:write"}}},
		},
	)
	if err != nil {
		t.Fatalf("BuildSchema: %v", err)
	}
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
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
	if ok, err := svc.Can(ctx, authkit.UserSubject(owner), authkit.GroupRef{Persona: "repo", Instance: "r1"}, "org:repo:read"); err != nil || !ok {
		t.Errorf("owner org:repo:read = %v,%v; want true", ok, err)
	}
	if ok, _ := svc.Can(ctx, authkit.UserSubject(owner), authkit.GroupRef{Persona: "repo", Instance: "r1"}, "repo:repo:write"); ok {
		t.Errorf("owner must NOT hold repo:repo:write (namespace purity)")
	}

	// A per-repo collaborator: no authority until assigned, then repo-scoped only.
	if ok, _ := svc.Can(ctx, authkit.UserSubject(dev), authkit.GroupRef{Persona: "repo", Instance: "r1"}, "repo:repo:write"); ok {
		t.Errorf("dev has no authority before assignment")
	}
	if err := svc.AssignGroupRole(ctx, authkit.GroupRef{Persona: "repo", Instance: "r1"}, authkit.UserSubject(dev), "writer"); err != nil {
		t.Fatalf("assign writer: %v", err)
	}
	if ok, err := svc.Can(ctx, authkit.UserSubject(dev), authkit.GroupRef{Persona: "repo", Instance: "r1"}, "repo:repo:write"); err != nil || !ok {
		t.Errorf("dev writer should hold repo:repo:write; got %v,%v", ok, err)
	}
	if ok, _ := svc.Can(ctx, authkit.UserSubject(dev), authkit.GroupRef{Persona: "org", Instance: "acme"}, "org:repo:read"); ok {
		t.Errorf("a repo collaborator must NOT gain org-scoped authority")
	}
	// While assigned, ListSubjectGroups shows the repo:r1 membership.
	if sg, err := svc.ListSubjectGroups(ctx, authkit.UserSubject(dev)); err != nil {
		t.Fatalf("ListSubjectGroups (assigned): %v", err)
	} else if len(sg) != 1 || sg[0].Persona != "repo" || sg[0].InstanceSlug != "r1" {
		t.Errorf("ListSubjectGroups(dev) should show the repo:r1 membership; got %+v", sg)
	}
	if err := svc.UnassignGroupRole(ctx, authkit.GroupRef{Persona: "repo", Instance: "r1"}, authkit.UserSubject(dev), "writer"); err != nil {
		t.Fatalf("remove writer: %v", err)
	}
	if ok, _ := svc.Can(ctx, authkit.UserSubject(dev), authkit.GroupRef{Persona: "repo", Instance: "r1"}, "repo:repo:write"); ok {
		t.Errorf("removing writer should remove the previous writer grant")
	}

	// Read surface: list a group's members + a subject's groups.
	members, err := svc.ListGroupMembers(ctx, authkit.GroupRef{Persona: "org", Instance: "acme"})
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
	// After removal, the membership is gone.
	sgroups, err := svc.ListSubjectGroups(ctx, authkit.UserSubject(dev))
	if err != nil {
		t.Fatalf("ListSubjectGroups: %v", err)
	}
	if len(sgroups) != 0 {
		t.Errorf("ListSubjectGroups(dev) should be empty after role removal; got %+v", sgroups)
	}

	// Role validation: repo disallows custom roles, so an unknown role is rejected.
	if err := svc.AssignGroupRole(ctx, authkit.GroupRef{Persona: "repo", Instance: "r1"}, authkit.UserSubject(dev), "nonsense"); err == nil {
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
	pool := testdb.Pool(t)
	ctx := context.Background()
	clean := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_persona_parents`)
	}
	clean()
	t.Cleanup(clean)

	gs, err := BuildSchema(PersonaDef{
		Name:         "org",
		Parent:       RootPersona,
		Capabilities: PersonaCapabilities{CustomRoles: true},
		Catalog:      []string{"org:billing:read"},
	})
	if err != nil {
		t.Fatalf("BuildSchema: %v", err)
	}
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	svc.groupSchema = gs
	if err := svc.SeedPermissionGroupContainment(ctx); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := svc.EnsureRootGroup(ctx); err != nil {
		t.Fatalf("root: %v", err)
	}
	var owner, uid string
	for _, p := range []*string{&owner, &uid} {
		if err := pool.QueryRow(ctx, `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(p); err != nil {
			t.Fatalf("create user: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id = ANY($1::uuid[])`, []string{owner, uid})
	})

	if _, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "org", InstanceSlug: "acme", OwnerSubjectID: owner}); err != nil {
		t.Fatalf("create org permission group: %v", err)
	}

	// define a custom role (as the owner — #247 requires an actor who covers
	// roles:manage + the role's grants), assign it to a non-owner, authorize.
	if err := svc.DefineGroupCustomRole(ctx, owner, authkit.GroupRef{Persona: "org", Instance: "acme"}, authkit.CustomRoleDef{Role: "auditor", Permissions: []string{"org:billing:read"}}); err != nil {
		t.Fatalf("DefineGroupCustomRole: %v", err)
	}
	if err := svc.AssignGroupRole(ctx, authkit.GroupRef{Persona: "org", Instance: "acme"}, authkit.UserSubject(uid), "auditor"); err != nil {
		t.Fatalf("assign auditor: %v", err)
	}
	if ok, err := svc.Can(ctx, authkit.UserSubject(uid), authkit.GroupRef{Persona: "org", Instance: "acme"}, "org:billing:read"); err != nil || !ok {
		t.Errorf("custom auditor role should grant org:billing:read; got %v,%v", ok, err)
	}
	if err := svc.RemoveGroupSubject(ctx, authkit.GroupRef{Persona: "org", Instance: "acme"}, authkit.UserSubject(uid)); err != nil {
		t.Fatalf("RemoveGroupSubject: %v", err)
	}
	if ok, _ := svc.Can(ctx, authkit.UserSubject(uid), authkit.GroupRef{Persona: "org", Instance: "acme"}, "org:billing:read"); ok {
		t.Errorf("removing a member should revoke custom-role grants too")
	}
	if err := svc.AssignGroupRole(ctx, authkit.GroupRef{Persona: "org", Instance: "acme"}, authkit.UserSubject(uid), "auditor"); err != nil {
		t.Fatalf("reassign auditor: %v", err)
	}
	// cross-persona custom perm is rejected (namespace purity).
	if err := svc.DefineGroupCustomRole(ctx, owner, authkit.GroupRef{Persona: "org", Instance: "acme"}, authkit.CustomRoleDef{Role: "bad", Permissions: []string{"repo:repo:read"}}); err == nil {
		t.Errorf("a cross-persona custom-role grant must be rejected")
	}
	if err := svc.DefineGroupCustomRole(ctx, owner, authkit.GroupRef{Persona: "org", Instance: "acme"}, authkit.CustomRoleDef{Role: "bad", Permissions: []string{"org:billing:write"}}); err == nil {
		t.Errorf("an outside-catalog custom-role grant must be rejected")
	}
	// a bounded actor with no roles:manage authority cannot redefine or delete.
	if err := svc.DefineGroupCustomRole(ctx, uid, authkit.GroupRef{Persona: "org", Instance: "acme"}, authkit.CustomRoleDef{Role: "auditor", Permissions: []string{"org:billing:read"}}); err == nil {
		t.Errorf("an actor without roles:manage must not be able to redefine a custom role")
	}
	if err := svc.DeleteGroupCustomRole(ctx, uid, authkit.GroupRef{Persona: "org", Instance: "acme"}, "auditor"); err == nil {
		t.Errorf("an actor without roles:manage must not be able to delete a custom role")
	}
	// delete -> the grant is gone.
	if err := svc.DeleteGroupCustomRole(ctx, owner, authkit.GroupRef{Persona: "org", Instance: "acme"}, "auditor"); err != nil {
		t.Fatalf("DeleteGroupCustomRole: %v", err)
	}
	if ok, _ := svc.Can(ctx, authkit.UserSubject(uid), authkit.GroupRef{Persona: "org", Instance: "acme"}, "org:billing:read"); ok {
		t.Errorf("after delete, the custom-role grant must be gone")
	}
}
