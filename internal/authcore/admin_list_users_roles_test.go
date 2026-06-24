package authcore

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"
)

// TestAdminListUsers_RoleEnrichmentParity verifies the batched root-role enrichment
// returns exactly what the per-user path (listRoleSlugsByUser) would, including the
// empty case — guarding the N+1 → single-query rewrite against behavior drift.
func TestAdminListUsers_RoleEnrichmentParity(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool))
	gs, err := BuildSchema(IntrinsicRootPersona(RoleDef{Name: "viewer"}))
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	svc.groupSchema = gs
	if _, err := svc.EnsureRootGroup(ctx); err != nil {
		t.Fatalf("ensure root group: %v", err)
	}

	prefix := fmt.Sprintf("listrole-%d-", time.Now().UnixNano())
	mk := func(tag string) string {
		var id string
		if err := pool.QueryRow(ctx, `INSERT INTO profiles.users (username) VALUES ($1) RETURNING id::text`, prefix+tag).Scan(&id); err != nil {
			t.Fatalf("create user %s: %v", tag, err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, id) })
		return id
	}
	withOwner, withViewer, noRole := mk("owner"), mk("viewer"), mk("norole")

	if err := svc.AssignGroupRole(ctx, RootPersona, "", withOwner, SubjectKindUser, OwnerRoleName); err != nil {
		t.Fatalf("assign owner: %v", err)
	}
	if err := svc.AssignGroupRole(ctx, RootPersona, "", withViewer, SubjectKindUser, "viewer"); err != nil {
		t.Fatalf("assign viewer: %v", err)
	}
	_ = noRole // intentionally left without a root role

	res, err := svc.AdminListUsers(ctx, AdminUserListOptions{Search: prefix, PageSize: 100})
	if err != nil {
		t.Fatalf("AdminListUsers: %v", err)
	}
	if len(res.Users) != 3 {
		t.Fatalf("expected 3 users for this run, got %d", len(res.Users))
	}
	for _, u := range res.Users {
		got := append([]string(nil), u.Roles...)
		want := append([]string(nil), svc.listRoleSlugsByUser(ctx, u.ID)...)
		sort.Strings(got)
		sort.Strings(want)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("user %s: batched roles %v != per-user roles %v", u.ID, got, want)
		}
	}
}
