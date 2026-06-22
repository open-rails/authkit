package core

import (
	"context"
	"testing"
)

// TestResolveRemoteApplicationAuthority proves the verifier's authority source
// returns ONLY role-derived permissions (#95: unify on roles), plus the
// assigned org memberships. A remote_application has no direct-permission grant.
func TestResolveRemoteApplicationAuthority(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool))

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

	memberships, perms, err := svc.ResolveRemoteApplicationAuthority(ctx, ra.ID)
	if err != nil {
		t.Fatalf("resolve authority: %v", err)
	}
	// Authority is role-derived ONLY (#95): the "ops" role expands to deploy:run.
	if len(perms) != 1 || perms[0] != "deploy:run" {
		t.Fatalf("perms=%v, want [deploy:run] (role-derived only)", perms)
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
