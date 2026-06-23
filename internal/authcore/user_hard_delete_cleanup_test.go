package authcore

import (
	"context"
	"testing"
)

// #125 D7: hard-deleting a user must clear their permission-group assignments
// (polymorphic trigger-FK, no cascade -> would orphan) and any invites they sent
// (group_invites.invited_by is ON DELETE RESTRICT -> would BLOCK the delete).
func TestAdminDeleteUserClearsGroupData(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	clean := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_invites`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_role_assignments`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_persona_parents`)
	}
	clean()
	t.Cleanup(clean)

	gs, err := BuildSchema(
		PersonaDef{
			Name: "org", AllowedParents: []string{RootPersona},
			Routes: ManagementProfile{MemberAssignment: true, Invitation: true},
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

	var owner, invitee string
	for _, p := range []*string{&owner, &invitee} {
		if err := pool.QueryRow(ctx, `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(p); err != nil {
			t.Fatalf("create user: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id = ANY($1::uuid[])`, []string{owner, invitee})
	})

	// owner gets a group assignment; owner also sends an invite to invitee.
	if _, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "org", ResourceSlug: "acme", OwnerSubjectID: owner}); err != nil {
		t.Fatalf("create org: %v", err)
	}
	if _, err := svc.CreateGroupInvite(ctx, "org", "acme", invitee, "member", owner); err != nil {
		t.Fatalf("CreateGroupInvite: %v", err)
	}

	countAssignments := func(uid string) int {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM profiles.group_role_assignments WHERE subject_id=$1::uuid AND subject_kind='user'`, uid).Scan(&n); err != nil {
			t.Fatalf("count assignments: %v", err)
		}
		return n
	}
	countInvitesBy := func(uid string) int {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM profiles.group_invites WHERE invited_by=$1::uuid`, uid).Scan(&n); err != nil {
			t.Fatalf("count invites: %v", err)
		}
		return n
	}

	if countAssignments(owner) == 0 {
		t.Fatalf("precondition: owner should hold an assignment")
	}
	if countInvitesBy(owner) == 0 {
		t.Fatalf("precondition: owner should have a sent invite")
	}

	// The hard delete must SUCCEED (the invited_by RESTRICT FK would otherwise
	// block it) and clear the owner's assignments + sent invites.
	if err := svc.AdminDeleteUser(ctx, owner); err != nil {
		t.Fatalf("AdminDeleteUser: %v", err)
	}

	if n := countAssignments(owner); n != 0 {
		t.Fatalf("after delete: %d orphaned assignments, want 0", n)
	}
	if n := countInvitesBy(owner); n != 0 {
		t.Fatalf("after delete: %d orphaned sent-invites, want 0", n)
	}
	var stillThere int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM profiles.users WHERE id=$1::uuid`, owner).Scan(&stillThere); err != nil {
		t.Fatalf("count user: %v", err)
	}
	if stillThere != 0 {
		t.Fatalf("owner user row should be hard-deleted")
	}
}
