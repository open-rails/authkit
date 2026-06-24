package authcore

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// grantsCoverAll is the heart of #136 no-escalation: an actor may grant a role
// only if it already holds every permission that role confers. These cases are
// pure over resolved grant sets (no DB).
func TestGrantsCoverAll_NoEscalation(t *testing.T) {
	owner := []string{"root:*"}
	admin := []string{"root:users:ban", "root:content:moderate", "root:admin-console:access"}
	weak := []string{"root:users:ban"}

	cases := []struct {
		name   string
		actor  []string
		target []string
		want   bool
	}{
		{"owner covers owner", owner, owner, true},
		{"owner covers admin", owner, admin, true},
		{"owner covers weak", owner, weak, true},
		{"admin covers itself (equal level ok)", admin, admin, true},
		{"admin covers weak subset", admin, weak, true},
		{"admin CANNOT cover owner (root:*)", admin, owner, false},
		{"weak CANNOT cover admin (more perms)", weak, admin, false},
		{"weak covers itself", weak, weak, true},
		{"weak CANNOT cover owner", weak, owner, false},
		{"nobody covers empty actor -> non-empty target", nil, weak, false},
		{"empty target is vacuously covered", weak, nil, true},
	}
	for _, tc := range cases {
		if got := grantsCoverAll(tc.actor, tc.target); got != tc.want {
			t.Errorf("%s: grantsCoverAll(%v, %v) = %v, want %v", tc.name, tc.actor, tc.target, got, tc.want)
		}
	}
}

// PermMatches treats `ns:*` (two segments) as the namespace-wide glob; a
// resource-scoped glob like `root:users:*` is a literal 3-segment grant whose
// last segment is `*`, and it covers `root:users:ban`. Verify that path so the
// subset check behaves for resource-scoped admin bundles.
func TestGrantsCoverAll_ResourceGlob(t *testing.T) {
	holder := []string{"root:users:*"} // matches root:users:<action>
	if !grantsCoverAll(holder, []string{"root:users:ban"}) {
		t.Fatalf("root:users:* should cover root:users:ban")
	}
	if grantsCoverAll(holder, []string{"root:content:moderate"}) {
		t.Fatalf("root:users:* must NOT cover root:content:moderate")
	}
	if grantsCoverAll(holder, []string{"root:*"}) {
		t.Fatalf("root:users:* must NOT cover the owner grant root:*")
	}
}

// TestAssignRoleBySlugAs_NoEscalation_DB exercises the #136 enforcement against a
// real DB: capability (root:members:manage) + no step-up (perms(role) ⊆ perms(actor)).
func TestAssignRoleBySlugAs_NoEscalation_DB(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()

	// Custom root schema: bounded `admin` (operational, NO members:manage) and a
	// `member-manager` (members:manage + users:ban, but NOT root:*). owner
	// (root:*) is auto-injected.
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
		uname := fmt.Sprintf("noesc-%s-%d", tag, suffix)
		var id string
		if err := pool.QueryRow(ctx, `INSERT INTO profiles.users (username) VALUES ($1) RETURNING id::text`, uname).Scan(&id); err != nil {
			t.Fatalf("create user %s: %v", tag, err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, id) })
		return id
	}
	owner, adminU, memberMgr, roleMgr, target := mk("owner"), mk("admin"), mk("membermgr"), mk("rolemgr"), mk("target")

	// Genesis: seed the owner via the unchecked path.
	if err := svc.AssignGroupRole(ctx, RootPersona, "", owner, SubjectKindUser, OwnerRoleName); err != nil {
		t.Fatalf("seed owner: %v", err)
	}

	// owner (root:*) may grant admin and member-manager (both ⊆ root:*).
	if err := svc.AssignRoleBySlugAs(ctx, owner, adminU, "admin"); err != nil {
		t.Fatalf("owner->admin should succeed: %v", err)
	}
	if err := svc.AssignRoleBySlugAs(ctx, owner, memberMgr, "member-manager"); err != nil {
		t.Fatalf("owner->member-manager should succeed: %v", err)
	}
	if err := svc.AssignRoleBySlugAs(ctx, owner, roleMgr, "role-manager"); err != nil {
		t.Fatalf("owner->role-manager should succeed: %v", err)
	}
	// owner may even mint another owner (owner covers owner).
	if err := svc.AssignRoleBySlugAs(ctx, owner, target, "owner"); err != nil {
		t.Fatalf("owner->owner should succeed: %v", err)
	}
	_ = svc.UnassignGroupRoleAs(ctx, owner, RootPersona, "", target, SubjectKindUser, "owner")

	// admin lacks root:members:manage → cannot grant anything.
	if err := svc.AssignRoleBySlugAs(ctx, adminU, target, "admin"); !errors.Is(err, ErrInsufficientRoleAuthority) {
		t.Fatalf("admin->admin want ErrInsufficientRoleAuthority, got %v", err)
	}

	// role-manager has only roles:manage, not members:manage → cannot assign members.
	if err := svc.AssignRoleBySlugAs(ctx, roleMgr, target, "admin"); !errors.Is(err, ErrInsufficientRoleAuthority) {
		t.Fatalf("role-manager->admin want ErrInsufficientRoleAuthority, got %v", err)
	}
	// member-manager HAS members:manage and covers admin's perms → may grant admin.
	if err := svc.AssignRoleBySlugAs(ctx, memberMgr, target, "admin"); err != nil {
		t.Fatalf("member-manager->admin should succeed: %v", err)
	}
	// but member-manager does NOT hold root:* → cannot grant owner (no step-up).
	if err := svc.AssignRoleBySlugAs(ctx, memberMgr, target, "owner"); !errors.Is(err, ErrRoleAssignmentEscalation) {
		t.Fatalf("member-manager->owner want ErrRoleAssignmentEscalation, got %v", err)
	}
}
