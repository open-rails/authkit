package core

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// #111 (DB): the `owner` role is assignable to a remote_application member of a
// permission-group, and it confers the type-namespace wildcard (`<type>:*`) that
// gives the issuer full authority within that group. Skips without
// AUTHKIT_TEST_DATABASE_URL.
func TestRemoteApplicationOwnerMembershipGrantsWildcard(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool))

	suffix := time.Now().UnixNano()
	gid, err := svc.EnsureRootGroup(ctx)
	if err != nil {
		t.Fatalf("ensure root group: %v", err)
	}
	ra, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{
		Slug:    fmt.Sprintf("ra-app-%d", suffix),
		OrgID:   gid, // permission_group_id (controlling group = root)
		Issuer:  fmt.Sprintf("https://app-%d.example", suffix),
		JWKSURI: fmt.Sprintf("https://app-%d.example/.well-known/jwks.json", suffix),
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("upsert remote_application: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.remote_applications WHERE id=$1::uuid`, ra.ID)
	})

	// The load-bearing assertion: owner is assignable to a remote_application.
	if err := svc.AddRemoteApplicationMember(ctx, ra.ID, OwnerRoleName); err != nil {
		t.Fatalf("add owner member to remote_application: %v", err)
	}

	roles, err := svc.RemoteApplicationRoles(ctx, ra.ID)
	if err != nil {
		t.Fatalf("remote_application roles: %v", err)
	}
	if !containsString(roles, OwnerRoleName) {
		t.Fatalf("remote_application should hold owner role, got %+v", roles)
	}

	perms, err := svc.ResolveRemoteApplicationAuthority(ctx, ra.ID)
	if err != nil {
		t.Fatalf("resolve remote_application authority: %v", err)
	}
	// owner of the root type holds the namespace-pure apex grant root:*.
	if !containsString(perms, OwnerGrant(RootType)) {
		t.Fatalf("owner role should confer %q; got perms=%v", OwnerGrant(RootType), perms)
	}
}
