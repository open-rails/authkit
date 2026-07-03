package authcore

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// TestPersonaRequireConsent covers the #193 per-persona join policy accessor and
// the root-defaults-to-instant rule (no DB).
func TestPersonaRequireConsent(t *testing.T) {
	gs, err := BuildSchema(
		IntrinsicRootPersona(), // root: RequireConsent defaults to false (instant)
		PersonaDef{Name: "team", Parent: RootPersona, RequireConsent: true},
		PersonaDef{Name: "repo", Parent: RootPersona}, // omitted => false
	)
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	if gs.RequireConsent(RootPersona) {
		t.Fatalf("root must default to instant (RequireConsent=false)")
	}
	if !gs.RequireConsent("team") {
		t.Fatalf("team should require consent")
	}
	if gs.RequireConsent("repo") {
		t.Fatalf("repo should be instant (RequireConsent unset)")
	}
	if gs.RequireConsent("nonexistent") {
		t.Fatalf("unknown persona must default to false")
	}
}

// TestLeaveGroupAndLastOwnerGuard_DB exercises self-leave + the shared last-owner
// guard against a real DB (#193): a member can drop their own role; a non-last owner
// can leave; the sole owner is refused (self-leave AND admin-remove).
func TestLeaveGroupAndLastOwnerGuard_DB(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()

	gs, err := BuildSchema(IntrinsicRootPersona(
		RoleDef{Name: "viewer", Permissions: []string{PermRootUsersBan}},
	))
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	svc.groupSchema = gs
	if _, err := svc.EnsureRootGroup(ctx); err != nil {
		t.Fatalf("ensure root group: %v", err)
	}

	suffix := time.Now().UnixNano()
	mk := func(tag string) string {
		var id string
		if err := pool.QueryRow(ctx, `INSERT INTO profiles.users (username) VALUES ($1) RETURNING id::text`,
			fmt.Sprintf("leave-%s-%d", tag, suffix)).Scan(&id); err != nil {
			t.Fatalf("create user %s: %v", tag, err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, id) })
		return id
	}
	owner1, owner2, viewer := mk("o1"), mk("o2"), mk("v")

	// Genesis seed (unchecked) — two owners and a bounded viewer.
	for _, s := range []struct{ id, role string }{
		{owner1, OwnerRoleName}, {owner2, OwnerRoleName}, {viewer, "viewer"},
	} {
		if err := svc.AssignGroupRole(ctx, RootPersona, "", s.id, SubjectKindUser, s.role); err != nil {
			t.Fatalf("seed %s: %v", s.role, err)
		}
	}

	can := func(uid, perm string) bool {
		ok, err := svc.Can(ctx, uid, SubjectKindUser, RootPersona, "", perm)
		if err != nil {
			t.Fatalf("Can(%s,%s): %v", uid, perm, err)
		}
		return ok
	}

	// Viewer self-leaves -> their role is gone.
	if !can(viewer, PermRootUsersBan) {
		t.Fatalf("viewer should hold the perm before leaving")
	}
	if err := svc.LeaveGroup(ctx, viewer, RootPersona, ""); err != nil {
		t.Fatalf("viewer leave: %v", err)
	}
	if can(viewer, PermRootUsersBan) {
		t.Fatalf("viewer should hold NO perm after leaving")
	}

	// Leaving a group you're not in is a no-op (idempotent).
	if err := svc.LeaveGroup(ctx, viewer, RootPersona, ""); err != nil {
		t.Fatalf("re-leave should be a no-op, got: %v", err)
	}

	// owner1 leaves while owner2 remains -> OK.
	if err := svc.LeaveGroup(ctx, owner1, RootPersona, ""); err != nil {
		t.Fatalf("non-last owner leave should succeed: %v", err)
	}

	// owner2 is now the sole owner -> self-leave refused (would orphan the group).
	if err := svc.LeaveGroup(ctx, owner2, RootPersona, ""); !errors.Is(err, ErrCannotRemoveLastAdminRole) {
		t.Fatalf("sole owner leave: got %v, want ErrCannotRemoveLastAdminRole", err)
	}
	if !can(owner2, "root:users:ban") {
		t.Fatalf("sole owner must still hold authority after a refused leave")
	}

	// The guard is shared: an admin removal of the sole owner is also refused.
	if err := svc.RemoveGroupSubjectAs(ctx, owner2, RootPersona, "", owner2, SubjectKindUser); !errors.Is(err, ErrCannotRemoveLastAdminRole) {
		t.Fatalf("admin-remove of sole owner: got %v, want ErrCannotRemoveLastAdminRole", err)
	}
}
