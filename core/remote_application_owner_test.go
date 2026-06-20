package core

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// #88(b) (DB): the `owner` role is assignable to a remote_application member —
// there is no reserved-role guard treating owner as human-founder-only — and it
// confers the wildcard permission that gives the issuer full authority over its
// merchant. Skips without AUTHKIT_TEST_DATABASE_URL.
func TestRemoteApplicationOwnerMembershipGrantsWildcard(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	suffix := time.Now().UnixNano()
	orgSlug := fmt.Sprintf("ra-owner-%d", suffix)
	org, err := svc.CreateOrg(ctx, orgSlug)
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	ra, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{
		Slug:    fmt.Sprintf("ra-app-%d", suffix),
		OrgID:   org.ID,
		Issuer:  fmt.Sprintf("https://app-%d.example", suffix),
		JWKSURI: fmt.Sprintf("https://app-%d.example/.well-known/jwks.json", suffix),
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("upsert remote_application: %v", err)
	}

	// The load-bearing assertion: owner is assignable to a remote_application.
	if err := svc.AddRemoteApplicationMember(ctx, org.Slug, ra.ID, "owner"); err != nil {
		t.Fatalf("add owner member to remote_application: %v", err)
	}

	memberships, perms, err := svc.ResolveRemoteApplicationAuthority(ctx, ra.ID)
	if err != nil {
		t.Fatalf("resolve remote_application authority: %v", err)
	}

	gotOwner := false
	for _, m := range memberships {
		if m.Org != orgSlug {
			continue
		}
		for _, r := range m.Roles {
			if r == "owner" {
				gotOwner = true
			}
		}
	}
	if !gotOwner {
		t.Fatalf("remote_application should hold owner role in %s, got memberships=%+v", orgSlug, memberships)
	}

	// owner = `org:*` (#95, tightened from a bare `*`), which EXPANDS to AuthKit's
	// full org base perm set for the remote_application member — full authority
	// over its merchant's org (but never the separate `platform:` layer).
	have := map[string]bool{}
	for _, p := range perms {
		have[p] = true
	}
	for _, d := range BasePermissions() {
		if !have[d.Name] {
			t.Fatalf("owner role should confer full org authority (missing %s); got perms=%v", d.Name, perms)
		}
	}
}
