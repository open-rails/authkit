package authcore

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/open-rails/authkit/internal/testdb"
)

func inviteTestService(t *testing.T, requiresMFA bool) (*Service, *testdb.Postgres, context.Context) {
	t.Helper()
	pg := testdb.ScratchPostgres(t)
	ctx := context.Background()
	gs, err := BuildSchema(PersonaDef{
		Name: "org", Parent: RootPersona,
		Roles: []RoleDef{{Name: "member", Permissions: []string{"org:repo:read"}, RequiresMFA: requiresMFA}},
	})
	if err != nil {
		t.Fatalf("BuildSchema: %v", err)
	}
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pg.Pool))
	svc.groupSchema = gs
	if err := svc.SeedPermissionGroupContainment(ctx); err != nil {
		t.Fatalf("SeedPermissionGroupContainment: %v", err)
	}
	if _, err := svc.EnsureRootGroup(ctx); err != nil {
		t.Fatalf("EnsureRootGroup: %v", err)
	}
	return svc, pg, ctx
}

func inviteState(t *testing.T, ctx context.Context, pg *testdb.Postgres, inviteID, userID string) (accepted bool, roleRows int) {
	t.Helper()
	if err := pg.Pool.QueryRow(ctx,
		`SELECT accepted_at IS NOT NULL,
		        (SELECT count(*) FROM profiles.group_user_roles r
		          WHERE r.permission_group_id = i.permission_group_id AND r.user_id = i.user_id AND r.deleted_at IS NULL)
		   FROM profiles.group_membership_invites i WHERE i.id = $1::uuid AND i.user_id = $2::uuid`,
		inviteID, userID).Scan(&accepted, &roleRows); err != nil {
		t.Fatalf("invite state: %v", err)
	}
	return accepted, roleRows
}

// #303: a refused MFA gate must leave the invite pending so the same invite
// can be accepted once the user enrolls.
func TestGroupMembershipInvite_MFARefusalKeepsInvitePending(t *testing.T) {
	svc, pg, ctx := inviteTestService(t, true)
	owner := insertBareUser(t, pg.Pool)
	invitee := insertBareUser(t, pg.Pool)
	if _, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "org", InstanceSlug: "acme", OwnerSubjectID: owner}); err != nil {
		t.Fatalf("CreatePermissionGroup: %v", err)
	}
	inv, err := svc.CreateGroupMembershipInvite(ctx, owner, "org", "acme", invitee, "member")
	if err != nil {
		t.Fatalf("CreateGroupMembershipInvite: %v", err)
	}

	if err := svc.AcceptGroupMembershipInvite(ctx, invitee, inv.ID); !errors.Is(err, ErrTwoFAEnrollmentRequired) {
		t.Fatalf("accept without MFA = %v, want ErrTwoFAEnrollmentRequired", err)
	}
	if accepted, roles := inviteState(t, ctx, pg, inv.ID, invitee); accepted || roles != 0 {
		t.Fatalf("after refusal accepted=%v roles=%d, want pending and no role", accepted, roles)
	}
	if pending, err := svc.ListPendingGroupMembershipInvites(ctx, invitee); err != nil || len(pending) != 1 || pending[0].ID != inv.ID {
		t.Fatalf("pending=%+v err=%v, want the refused invite still listed", pending, err)
	}

	if _, err := svc.Enable2FA(ctx, invitee, "email", nil); err != nil {
		t.Fatalf("Enable2FA: %v", err)
	}
	if err := svc.AcceptGroupMembershipInvite(ctx, invitee, inv.ID); err != nil {
		t.Fatalf("accept after enrollment: %v", err)
	}
	if accepted, roles := inviteState(t, ctx, pg, inv.ID, invitee); !accepted || roles != 1 {
		t.Fatalf("after accept accepted=%v roles=%d", accepted, roles)
	}
	if ok, err := svc.Can(ctx, invitee, SubjectKindUser, "org", "acme", "org:repo:read"); err != nil || !ok {
		t.Fatalf("invitee should hold org:repo:read; got %v,%v", ok, err)
	}
}

// #303: concurrent accepts of one invite grant exactly once; every other
// caller sees the invite as consumed.
func TestGroupMembershipInvite_ConcurrentAcceptsConsumeOnce(t *testing.T) {
	svc, pg, ctx := inviteTestService(t, false)
	owner := insertBareUser(t, pg.Pool)
	invitee := insertBareUser(t, pg.Pool)
	if _, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "org", InstanceSlug: "acme", OwnerSubjectID: owner}); err != nil {
		t.Fatalf("CreatePermissionGroup: %v", err)
	}
	inv, err := svc.CreateGroupMembershipInvite(ctx, owner, "org", "acme", invitee, "member")
	if err != nil {
		t.Fatalf("CreateGroupMembershipInvite: %v", err)
	}

	const n = 8
	start := make(chan struct{})
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = svc.AcceptGroupMembershipInvite(ctx, invitee, inv.ID)
		}(i)
	}
	close(start)
	wg.Wait()

	wins := 0
	for i, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrGroupMembershipInviteNotFound):
		default:
			t.Fatalf("accept %d: unexpected %v", i, err)
		}
	}
	if wins != 1 {
		t.Fatalf("wins=%d, want exactly one", wins)
	}
	if accepted, roles := inviteState(t, ctx, pg, inv.ID, invitee); !accepted || roles != 1 {
		t.Fatalf("accepted=%v roles=%d, want one accepted invite and one role row", accepted, roles)
	}
}
