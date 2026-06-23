package authcore

import (
	"context"
	"testing"
)

// TestPermissionGroupStore_WalkAndAuthorize exercises the DB-backed engine
// end-to-end against a real Postgres (skips without AUTHKIT_TEST_DATABASE_URL,
// which must point at a DB migrated through 008). Everything runs in a single
// transaction that is rolled back, so it leaves no residue.
func TestPermissionGroupStore_WalkAndAuthorize(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	clean := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_remote_application_roles`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_user_roles`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_custom_roles`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_persona_parents`)
	}
	clean()
	t.Cleanup(clean)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := NewPermissionGroupStore(tx)

	schema, err := BuildSchema(
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
	if err := st.SeedContainment(ctx, schema); err != nil {
		t.Fatalf("SeedContainment: %v", err)
	}

	// Build the tree root -> org(acme) -> repo(r1).
	rootID, err := st.CreateGroup(ctx, "root", "", "", "")
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	orgID, err := st.CreateGroup(ctx, "org", rootID, "root", "acme")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	repoID, err := st.CreateGroup(ctx, "repo", orgID, "org", "r1")
	if err != nil {
		t.Fatalf("create repo: %v", err)
	}

	// Containment: root -> repo must be rejected by the DB trigger. Run in a
	// SAVEPOINT so the expected failure doesn't abort the outer transaction.
	func() {
		sp, err := tx.Begin(ctx)
		if err != nil {
			t.Fatalf("savepoint: %v", err)
		}
		defer func() { _ = sp.Rollback(ctx) }()
		if _, err := NewPermissionGroupStore(sp).CreateGroup(ctx, "repo", rootID, "root", "rX"); err == nil {
			t.Errorf("root->repo should be rejected by the containment trigger")
		}
	}()

	// A user who OWNS the org (assignment lives at the org level).
	var uid string
	if err := tx.QueryRow(ctx, `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(&uid); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := st.AssignRole(ctx, orgID, uid, SubjectKindUser, OwnerRoleName); err != nil {
		t.Fatalf("assign owner: %v", err)
	}

	// Walk from the repo surfaces the org-owner assignment (and nothing else).
	asg, err := st.WalkAssignments(ctx, repoID, uid, SubjectKindUser)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(asg) != 1 || asg[0].Persona != "org" || len(asg[0].Roles) != 1 || asg[0].Roles[0] != OwnerRoleName {
		t.Fatalf("walk = %+v, want one org/owner assignment", asg)
	}

	// Authorize via walk-up: org owner (org:*) reaches org:repo:read on the repo,
	// but NOT repo:repo:write (namespace purity — reach != capability).
	if ok, err := st.CanOnGroup(ctx, schema, uid, SubjectKindUser, repoID, "org:repo:read"); err != nil || !ok {
		t.Errorf("CanOnGroup org:repo:read = %v,%v; want true", ok, err)
	}
	if ok, _ := st.CanOnGroup(ctx, schema, uid, SubjectKindUser, repoID, "repo:repo:write"); ok {
		t.Errorf("org owner must NOT hold repo:repo:write")
	}

	// Resource addressing: (type, resource_slug) -> internal id.
	if got, err := st.GroupByResourceSlug(ctx, "org", "acme"); err != nil || got != orgID {
		t.Errorf("GroupByResourceSlug(org,acme) = %q,%v; want %q", got, err, orgID)
	}

	// Custom role (org opted into AllowCustomRoles): define it, then assign it to
	// a SECOND user who is NOT the owner — so the grant comes solely from the
	// custom role (the owner's org:* would otherwise mask the test).
	var uid2 string
	if err := tx.QueryRow(ctx, `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(&uid2); err != nil {
		t.Fatalf("create user2: %v", err)
	}
	if err := st.UpsertCustomRole(ctx, orgID, "auditor", []string{"org:billing:read"}); err != nil {
		t.Fatalf("UpsertCustomRole: %v", err)
	}
	// before assignment: no authority.
	if ok, _ := st.CanOnGroup(ctx, schema, uid2, SubjectKindUser, orgID, "org:billing:read"); ok {
		t.Errorf("unassigned user must have no authority")
	}
	if err := st.AssignRole(ctx, orgID, uid2, SubjectKindUser, "auditor"); err != nil {
		t.Fatalf("assign auditor: %v", err)
	}
	if ok, err := st.CanOnGroup(ctx, schema, uid2, SubjectKindUser, orgID, "org:billing:read"); err != nil || !ok {
		t.Errorf("custom auditor role should authorize org:billing:read; got %v,%v", ok, err)
	}
	// the custom role is namespace-scoped: it does NOT grant repo authority.
	if ok, _ := st.CanOnGroup(ctx, schema, uid2, SubjectKindUser, orgID, "org:repo:read"); ok {
		t.Errorf("auditor (org:billing:read only) must NOT cover org:repo:read")
	}
	// UnassignRole revokes.
	if err := st.UnassignRole(ctx, orgID, uid2, SubjectKindUser, "auditor"); err != nil {
		t.Fatalf("unassign: %v", err)
	}
	if ok, _ := st.CanOnGroup(ctx, schema, uid2, SubjectKindUser, orgID, "org:billing:read"); ok {
		t.Errorf("after unassign, auditor grant must be gone")
	}
}
