package authcore

import (
	"errors"
	"testing"
)

// #147 known-user consent invite: an owner invites an EXISTING user; the invitee
// holds the role only AFTER they accept (own-auth), and a decline leaves them out.
func TestGroupMembershipInvite_AcceptGrantsRole(t *testing.T) {
	svc, pool, ctx := setupInviteLinkTest(t, RegistrationModeOpen)
	owner := acmeOwner(t, svc, ctx, pool)
	target := insertBareUser(t, pool)

	inv, err := svc.CreateGroupMembershipInvite(ctx, owner, "org", "acme", target, "member")
	if err != nil {
		t.Fatalf("CreateGroupMembershipInvite: %v", err)
	}

	// Not a member until accepted.
	if ok, _ := svc.Can(ctx, target, SubjectKindUser, "org", "acme", "org:repo:read"); ok {
		t.Fatal("target must not hold the role before accepting")
	}
	// The invite shows up in the target's pending list.
	pending, err := svc.ListPendingGroupMembershipInvites(ctx, target)
	if err != nil || len(pending) != 1 || pending[0].ID != inv.ID || pending[0].Role != "member" {
		t.Fatalf("pending = %+v err=%v", pending, err)
	}

	// Accept (own-auth) → role granted.
	if err := svc.AcceptGroupMembershipInvite(ctx, target, inv.ID); err != nil {
		t.Fatalf("AcceptGroupMembershipInvite: %v", err)
	}
	mustHoldMember(t, svc, ctx, target)

	// Single-use: re-accepting the now-consumed invite is rejected.
	if err := svc.AcceptGroupMembershipInvite(ctx, target, inv.ID); !errors.Is(err, ErrGroupMembershipInviteNotFound) {
		t.Fatalf("re-accept = %v, want ErrGroupMembershipInviteNotFound", err)
	}
}

func TestGroupMembershipInvite_DeclineDoesNotGrant(t *testing.T) {
	svc, pool, ctx := setupInviteLinkTest(t, RegistrationModeOpen)
	owner := acmeOwner(t, svc, ctx, pool)
	target := insertBareUser(t, pool)

	inv, err := svc.CreateGroupMembershipInvite(ctx, owner, "org", "acme", target, "member")
	if err != nil {
		t.Fatalf("CreateGroupMembershipInvite: %v", err)
	}
	if err := svc.DeclineGroupMembershipInvite(ctx, target, inv.ID); err != nil {
		t.Fatalf("DeclineGroupMembershipInvite: %v", err)
	}
	if ok, _ := svc.Can(ctx, target, SubjectKindUser, "org", "acme", "org:repo:read"); ok {
		t.Fatal("declined invite must not grant the role")
	}
	if pending, _ := svc.ListPendingGroupMembershipInvites(ctx, target); len(pending) != 0 {
		t.Fatalf("declined invite should not be pending, got %d", len(pending))
	}
}

// A non-owner without members:manage authority cannot mint an invite (same
// no-escalation gate as a direct assignment).
func TestGroupMembershipInvite_RequiresAuthority(t *testing.T) {
	svc, pool, ctx := setupInviteLinkTest(t, RegistrationModeOpen)
	stranger := insertBareUser(t, pool)
	target := insertBareUser(t, pool)
	if _, err := svc.CreateGroupMembershipInvite(ctx, stranger, "org", "acme", target, "member"); err == nil {
		t.Fatal("a non-authorized actor must not be able to invite")
	}
}
