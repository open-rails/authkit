package core

import (
	"context"
	"testing"
)

// TestService_GroupInviteFlow drives the invite lifecycle end-to-end against a
// real Postgres (skips without AUTHKIT_TEST_DATABASE_URL; DB migrated through
// 008). It asserts create -> list -> accept assigns the invited role (verified
// via svc.Can), plus decline + revoke transitions. The service methods commit
// their own transactions, so the test wipes the permission-group tables around
// itself (disposable test DB).
func TestService_GroupInviteFlow(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	clean := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_invites`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_role_assignments`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_type_parents`)
	}
	clean()
	t.Cleanup(clean)

	gs, err := BuildSchema(
		GroupTypeDef{
			Name: "org", AllowedParents: []string{RootType},
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

	var owner, invitee, decliner string
	for _, p := range []*string{&owner, &invitee, &decliner} {
		if err := pool.QueryRow(ctx, `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(p); err != nil {
			t.Fatalf("create user: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id = ANY($1::uuid[])`, []string{owner, invitee, decliner})
	})

	if _, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Type: "org", ResourceRef: "acme", OwnerSubjectID: owner}); err != nil {
		t.Fatalf("create org: %v", err)
	}

	// Role validation: an unknown role for a fixed-catalog type is rejected.
	if _, err := svc.CreateGroupInvite(ctx, "org", "acme", invitee, "nonsense", owner); err == nil {
		t.Errorf("invite with an unknown role should be rejected")
	}

	// Create a pending invite for the "member" role.
	inviteID, err := svc.CreateGroupInvite(ctx, "org", "acme", invitee, "member", owner)
	if err != nil {
		t.Fatalf("CreateGroupInvite: %v", err)
	}
	if inviteID == "" {
		t.Fatalf("CreateGroupInvite returned empty id")
	}

	// List shows the pending invite.
	invites, err := svc.ListGroupInvites(ctx, "org", "acme")
	if err != nil {
		t.Fatalf("ListGroupInvites: %v", err)
	}
	if len(invites) != 1 || invites[0].ID != inviteID || invites[0].Status != GroupInviteStatusPending ||
		invites[0].UserID != invitee || invites[0].Role != "member" {
		t.Fatalf("ListGroupInvites mismatch: %+v", invites)
	}

	// Before accept: invitee holds no authority.
	if ok, _ := svc.Can(ctx, invitee, SubjectKindUser, "org", "acme", "org:repo:read"); ok {
		t.Errorf("invitee must NOT hold authority before accepting")
	}

	// Accept assigns the invited role (verified via Can) and flips status.
	if err := svc.AcceptGroupInvite(ctx, inviteID, invitee); err != nil {
		t.Fatalf("AcceptGroupInvite: %v", err)
	}
	if ok, err := svc.Can(ctx, invitee, SubjectKindUser, "org", "acme", "org:repo:read"); err != nil || !ok {
		t.Errorf("invitee should hold org:repo:read after accept; got %v,%v", ok, err)
	}
	after, _ := svc.ListGroupInvites(ctx, "org", "acme")
	if len(after) != 1 || after[0].Status != GroupInviteStatusAccepted || after[0].ActedAt == nil {
		t.Errorf("invite should be accepted with acted_at set; got %+v", after)
	}

	// Idempotency / wrong-state: re-accepting an accepted invite is not-pending.
	if err := svc.AcceptGroupInvite(ctx, inviteID, invitee); err != ErrInviteNotPending {
		t.Errorf("re-accept = %v; want ErrInviteNotPending", err)
	}

	// Accept with the wrong user => not found (scoped to the invited user).
	id2, err := svc.CreateGroupInvite(ctx, "org", "acme", decliner, "member", owner)
	if err != nil {
		t.Fatalf("CreateGroupInvite(decliner): %v", err)
	}
	if err := svc.AcceptGroupInvite(ctx, id2, invitee); err != ErrInviteNotFound {
		t.Errorf("accept by non-invited user = %v; want ErrInviteNotFound", err)
	}

	// Decline transitions to declined and assigns nothing.
	if err := svc.DeclineGroupInvite(ctx, id2, decliner); err != nil {
		t.Fatalf("DeclineGroupInvite: %v", err)
	}
	if ok, _ := svc.Can(ctx, decliner, SubjectKindUser, "org", "acme", "org:repo:read"); ok {
		t.Errorf("decliner must hold no authority after declining")
	}
	if err := svc.DeclineGroupInvite(ctx, id2, decliner); err != ErrInviteNotPending {
		t.Errorf("re-decline = %v; want ErrInviteNotPending", err)
	}

	// Revoke a fresh pending invite (group-scoped); re-revoke is not-pending.
	id3, err := svc.CreateGroupInvite(ctx, "org", "acme", decliner, "member", owner)
	if err != nil {
		t.Fatalf("CreateGroupInvite(revoke target): %v", err)
	}
	if err := svc.RevokeGroupInvite(ctx, "org", "acme", id3); err != nil {
		t.Fatalf("RevokeGroupInvite: %v", err)
	}
	if err := svc.RevokeGroupInvite(ctx, "org", "acme", id3); err != ErrInviteNotPending {
		t.Errorf("re-revoke = %v; want ErrInviteNotPending", err)
	}

	// Revoke an unknown id => not found.
	if err := svc.RevokeGroupInvite(ctx, "org", "acme", "00000000-0000-0000-0000-000000000000"); err != ErrInviteNotFound {
		t.Errorf("revoke unknown invite = %v; want ErrInviteNotFound", err)
	}
}
