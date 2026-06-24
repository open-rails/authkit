package authcore

import (
	"context"
	"testing"
)

// TestPermissionGroups_ParentDeleteCascadesSubtree pins the teardown semantics of
// the self-referential FK profiles.permission_groups.parent_id ON DELETE CASCADE:
// a HARD delete of any group cascades to its entire descendant subtree AND to the
// authority rows (group_user_roles, and likewise api_keys / invite-links / remote
// apps) hanging off those descendants.
//
// DECISION (v1.0.0 freeze, 2026-06-24): keep ON DELETE CASCADE and make it
// INTENTIONAL via this characterization test. The application never hard-deletes
// permission_groups (it soft-deletes via deleted_at), so the cascade is latent —
// it only fires on an explicit DELETE. Recorded follow-up (not done here, needs a
// new migration + maintainer sign-off): switch parent_id to ON DELETE RESTRICT so
// a mid-tree group cannot be hard-deleted out from under its children. If that
// migration lands, this test's expectations flip and document the new contract.
func TestPermissionGroups_ParentDeleteCascadesSubtree(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	clean := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_user_roles`)
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
		PersonaDef{Name: "org", AllowedParents: []string{RootPersona}, Roles: []RoleDef{{Name: "member", Permissions: []string{"org:repo:read"}}}},
		PersonaDef{Name: "repo", AllowedParents: []string{"org"}, Roles: []RoleDef{{Name: "writer", Permissions: []string{"repo:repo:write"}}}},
	)
	if err != nil {
		t.Fatalf("BuildSchema: %v", err)
	}
	if err := st.SeedContainment(ctx, schema); err != nil {
		t.Fatalf("SeedContainment: %v", err)
	}

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

	// Authority on the deepest (grandchild) group.
	var uid string
	if err := tx.QueryRow(ctx, `INSERT INTO profiles.users (username) VALUES ('cascade-victim') RETURNING id::text`).Scan(&uid); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO profiles.group_user_roles (permission_group_id, user_id, role) VALUES ($1::uuid,$2::uuid,'writer')`, repoID, uid); err != nil {
		t.Fatalf("seed repo role: %v", err)
	}

	// Hard-delete the MIDDLE group. CASCADE must wipe org + repo (subtree) and the
	// repo's authority row with it.
	if _, err := tx.Exec(ctx, `DELETE FROM profiles.permission_groups WHERE id=$1::uuid`, orgID); err != nil {
		t.Fatalf("delete org: %v", err)
	}

	var groups int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM profiles.permission_groups WHERE id = ANY($1::uuid[])`, []string{orgID, repoID}).Scan(&groups); err != nil {
		t.Fatalf("count groups: %v", err)
	}
	if groups != 0 {
		t.Fatalf("deleting the mid-tree group must cascade to its subtree; %d of {org,repo} survived", groups)
	}

	var roles int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM profiles.group_user_roles WHERE permission_group_id = $1::uuid`, repoID).Scan(&roles); err != nil {
		t.Fatalf("count roles: %v", err)
	}
	if roles != 0 {
		t.Fatalf("subtree cascade must remove descendant authority rows; %d repo roles survived", roles)
	}

	// The root group (above the deleted node) is untouched.
	var rootAlive int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM profiles.permission_groups WHERE id = $1::uuid`, rootID).Scan(&rootAlive); err != nil {
		t.Fatalf("count root: %v", err)
	}
	if rootAlive != 1 {
		t.Fatalf("ancestor (root) must survive deletion of a descendant; got %d", rootAlive)
	}
}
