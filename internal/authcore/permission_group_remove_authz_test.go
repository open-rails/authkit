package authcore

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// TestRemoveGroupSubjectAs_NoEscalation_DB verifies #136 enforcement on the REVOKE
// path: a holder of root:members:manage that does NOT hold root:* cannot strip an
// owner's roles, while an owner can. Mirrors the assign-path no-escalation test.
func TestRemoveGroupSubjectAs_NoEscalation_DB(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()

	gs, err := BuildSchema(IntrinsicRootPersona(
		RoleDef{Name: "admin", Permissions: []string{PermRootUsersBan}},
		RoleDef{Name: "member-manager", Permissions: []string{PermMembersManage(RootPersona), PermRootUsersBan}},
		RoleDef{Name: "role-manager", Permissions: []string{PermRolesManage(RootPersona), PermRootUsersBan}},
	))
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool))
	svc.groupSchema = gs
	if _, err := svc.EnsureRootGroup(ctx); err != nil {
		t.Fatalf("ensure root group: %v", err)
	}

	suffix := time.Now().UnixNano()
	mk := func(tag string) string {
		uname := fmt.Sprintf("rmesc-%s-%d", tag, suffix)
		var id string
		if err := pool.QueryRow(ctx, `INSERT INTO profiles.users (username) VALUES ($1) RETURNING id::text`, uname).Scan(&id); err != nil {
			t.Fatalf("create user %s: %v", tag, err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, id) })
		return id
	}
	owner, memberMgr, roleMgr, ownerTarget, weakTarget := mk("owner"), mk("membermgr"), mk("rolemgr"), mk("ownertgt"), mk("weaktgt")

	// Genesis seeding via the unchecked path.
	if err := svc.AssignGroupRole(ctx, RootPersona, "", owner, SubjectKindUser, OwnerRoleName); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	if err := svc.AssignGroupRole(ctx, RootPersona, "", memberMgr, SubjectKindUser, "member-manager"); err != nil {
		t.Fatalf("seed member-manager: %v", err)
	}
	if err := svc.AssignGroupRole(ctx, RootPersona, "", roleMgr, SubjectKindUser, "role-manager"); err != nil {
		t.Fatalf("seed role-manager: %v", err)
	}
	if err := svc.AssignGroupRole(ctx, RootPersona, "", ownerTarget, SubjectKindUser, OwnerRoleName); err != nil {
		t.Fatalf("seed owner target: %v", err)
	}
	if err := svc.AssignGroupRole(ctx, RootPersona, "", weakTarget, SubjectKindUser, "admin"); err != nil {
		t.Fatalf("seed weak target: %v", err)
	}

	// role-manager has only roles:manage, not members:manage → cannot remove members.
	if err := svc.RemoveGroupSubjectAs(ctx, roleMgr, RootPersona, "", weakTarget, SubjectKindUser); !errors.Is(err, ErrInsufficientRoleAuthority) {
		t.Fatalf("role-manager removing admin: want ErrInsufficientRoleAuthority, got %v", err)
	}
	// member-manager (members:manage, but NOT root:*) cannot remove an owner.
	if err := svc.RemoveGroupSubjectAs(ctx, memberMgr, RootPersona, "", ownerTarget, SubjectKindUser); !errors.Is(err, ErrRoleAssignmentEscalation) {
		t.Fatalf("member-manager removing owner: want ErrRoleAssignmentEscalation, got %v", err)
	}
	// member-manager CAN remove a member whose roles it covers (admin ⊆ member-manager).
	if err := svc.RemoveGroupSubjectAs(ctx, memberMgr, RootPersona, "", weakTarget, SubjectKindUser); err != nil {
		t.Fatalf("member-manager removing admin (covered) should succeed: %v", err)
	}
	// owner (root:*) CAN remove another owner.
	if err := svc.RemoveGroupSubjectAs(ctx, owner, RootPersona, "", ownerTarget, SubjectKindUser); err != nil {
		t.Fatalf("owner removing owner should succeed: %v", err)
	}
}
