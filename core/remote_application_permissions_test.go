package core

import (
	"context"
	"testing"
)

// TestRemoteApplicationDirectPermissions exercises the direct-permission grant
// (#76): add (idempotent) -> list -> remove, the STORED authority surface that
// mirrors service_token_permissions.
func TestRemoteApplicationDirectPermissions(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	const aslug = "perm-app"
	const iss = "https://perm-app.example/iss"
	orgID := createTestOrg(t, ctx, svc, pool, "perm-app-org")
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, aslug)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, aslug) })

	ra, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{Slug: aslug, OrgID: orgID, Issuer: iss, JWKSURI: "https://perm-app.example/jwks.json", Enabled: true})
	if err != nil {
		t.Fatalf("create remote_application: %v", err)
	}

	if err := svc.AddRemoteApplicationPermission(ctx, ra.ID, "billing:read"); err != nil {
		t.Fatalf("add perm: %v", err)
	}
	// Idempotent: re-granting is a no-op.
	if err := svc.AddRemoteApplicationPermission(ctx, ra.ID, "billing:read"); err != nil {
		t.Fatalf("re-add perm: %v", err)
	}
	if err := svc.AddRemoteApplicationPermission(ctx, ra.ID, "jobs:submit"); err != nil {
		t.Fatalf("add perm 2: %v", err)
	}

	perms, err := svc.ListRemoteApplicationPermissions(ctx, ra.ID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(perms) != 2 {
		t.Fatalf("perms=%v, want 2", perms)
	}

	removed, err := svc.RemoveRemoteApplicationPermission(ctx, ra.ID, "billing:read")
	if err != nil || !removed {
		t.Fatalf("remove removed=%v err=%v", removed, err)
	}
	// Removing again returns false.
	removed, err = svc.RemoveRemoteApplicationPermission(ctx, ra.ID, "billing:read")
	if err != nil || removed {
		t.Fatalf("re-remove removed=%v err=%v, want false", removed, err)
	}
}

// TestResolveRemoteApplicationAuthority proves the verifier's authority source
// returns direct permissions UNION role-derived permissions, plus the assigned
// org memberships (#76).
func TestResolveRemoteApplicationAuthority(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	const tslug = "authority-org"
	const aslug = "authority-app"
	const iss = "https://authority-app.example/iss"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, aslug)
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, tslug)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, aslug)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, tslug)
	})

	org, err := svc.CreateOrg(ctx, tslug)
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	ra, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{Slug: aslug, OrgID: org.ID, Issuer: iss, JWKSURI: "https://authority-app.example/jwks.json", Enabled: true})
	if err != nil {
		t.Fatalf("create remote_application: %v", err)
	}

	if err := svc.DefineRole(ctx, tslug, "ops"); err != nil {
		t.Fatalf("define role: %v", err)
	}
	if err := svc.SetRolePermissions(ctx, tslug, "ops", []string{"deploy:run"}); err != nil {
		t.Fatalf("set role perms: %v", err)
	}
	if err := svc.AddRemoteApplicationMember(ctx, tslug, ra.ID, "ops"); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if err := svc.AddRemoteApplicationPermission(ctx, ra.ID, "secrets:read"); err != nil {
		t.Fatalf("add direct perm: %v", err)
	}

	memberships, perms, err := svc.ResolveRemoteApplicationAuthority(ctx, ra.ID)
	if err != nil {
		t.Fatalf("resolve authority: %v", err)
	}
	wantPerms := map[string]bool{"deploy:run": true, "secrets:read": true}
	if len(perms) != 2 {
		t.Fatalf("perms=%v, want deploy:run+secrets:read", perms)
	}
	for _, p := range perms {
		if !wantPerms[p] {
			t.Fatalf("unexpected perm %q in %v", p, perms)
		}
	}
	foundOrg := false
	for _, m := range memberships {
		if m.Org == tslug {
			foundOrg = true
		}
	}
	if !foundOrg {
		t.Fatalf("org membership not resolved: %+v", memberships)
	}
}
