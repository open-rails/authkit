package authcore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/db"
)

// #282: issuer ownership never moves across permission groups — neither via
// the service guard nor via the store upsert on its own, and not under
// concurrent registration from two groups.
func TestUpsertRemoteApplicationIssuerOwnershipIsGroupImmutable(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()

	gs, err := BuildSchema(PersonaDef{
		Name: "org", Parent: RootPersona,
		Capabilities: PersonaCapabilities{RemoteApplications: true},
		Roles:        []RoleDef{{Name: "member", Permissions: []string{"org:repo:read"}}},
	})
	if err != nil {
		t.Fatalf("BuildSchema: %v", err)
	}
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	svc.groupSchema = gs
	if err := svc.SeedPermissionGroupContainment(ctx); err != nil {
		t.Fatalf("SeedPermissionGroupContainment: %v", err)
	}
	if _, err := svc.EnsureRootGroup(ctx); err != nil {
		t.Fatalf("EnsureRootGroup: %v", err)
	}
	suffix := time.Now().UnixNano()
	slugA, slugB := fmt.Sprintf("ra-iss-a-%d", suffix), fmt.Sprintf("ra-iss-b-%d", suffix)
	groupA, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "org", InstanceSlug: slugA})
	if err != nil {
		t.Fatalf("create group A: %v", err)
	}
	groupB, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "org", InstanceSlug: slugB})
	if err != nil {
		t.Fatalf("create group B: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE issuer LIKE $1`, fmt.Sprintf("https://iss-%d.example%%", suffix))
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups WHERE persona='org' AND instance_slug IN ($1,$2)`, slugA, slugB)
	})
	ownerOf := func(issuer string) (gid, slug, jwks string) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT permission_group_id::text, slug, jwks_uri FROM profiles.remote_applications WHERE issuer=$1`, issuer).Scan(&gid, &slug, &jwks); err != nil {
			t.Fatalf("row for %s: %v", issuer, err)
		}
		return
	}
	reg := func(gid, slug, issuer, jwks string) RemoteApplication {
		return RemoteApplication{Slug: slug, PermissionGroupID: gid, Issuer: issuer, JWKSURI: jwks, Enabled: true}
	}

	// Sequential: B cannot take A's issuer; A can rotate it.
	issuer := fmt.Sprintf("https://iss-%d.example/seq", suffix)
	if _, err := svc.UpsertRemoteApplication(ctx, reg(groupA, "ra-a-"+fmt.Sprint(suffix), issuer, "https://a.example/jwks.json")); err != nil {
		t.Fatalf("A registers: %v", err)
	}
	if _, err := svc.UpsertRemoteApplication(ctx, reg(groupB, "ra-b-"+fmt.Sprint(suffix), issuer, "https://b.example/jwks.json")); !errors.Is(err, ErrRemoteApplicationIssuerConflict) {
		t.Fatalf("B takeover = %v, want ErrRemoteApplicationIssuerConflict", err)
	}
	if gid, _, jwks := ownerOf(issuer); gid != groupA || jwks != "https://a.example/jwks.json" {
		t.Fatalf("row moved: gid=%s jwks=%s", gid, jwks)
	}
	if _, err := svc.UpsertRemoteApplication(ctx, reg(groupA, "ra-a-"+fmt.Sprint(suffix), issuer, "https://a.example/rotated.json")); err != nil {
		t.Fatalf("A rotates: %v", err)
	}
	if gid, _, jwks := ownerOf(issuer); gid != groupA || jwks != "https://a.example/rotated.json" {
		t.Fatalf("A rotation lost: gid=%s jwks=%s", gid, jwks)
	}

	// Store alone: bypassing the service guard, the ON CONFLICT clause refuses
	// the cross-group move outright.
	_, err = svc.q.RemoteApplicationUpsert(ctx, db.RemoteApplicationUpsertParams{
		Slug: "ra-b-direct-" + fmt.Sprint(suffix), PermissionGroupID: &groupB, Issuer: issuer,
		JwksUri: "https://b.example/jwks.json", Mode: RemoteAppModeJWKS, Enabled: true,
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("direct store takeover = %v, want pgx.ErrNoRows", err)
	}
	if gid, slug, jwks := ownerOf(issuer); gid != groupA || slug != "ra-a-"+fmt.Sprint(suffix) || jwks != "https://a.example/rotated.json" {
		t.Fatalf("store moved row: gid=%s slug=%s jwks=%s", gid, slug, jwks)
	}

	// Concurrent: both groups race to register a fresh issuer; exactly one
	// group wins, every loss is the typed conflict, and the row ends with the
	// winner.
	raceIssuer := fmt.Sprintf("https://iss-%d.example/race", suffix)
	const perGroup = 4
	type result struct {
		gid string
		err error
	}
	results := make(chan result, 2*perGroup)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < perGroup; i++ {
		for _, gid := range []string{groupA, groupB} {
			wg.Add(1)
			go func(gid string, i int) {
				defer wg.Done()
				<-start
				_, err := svc.UpsertRemoteApplication(ctx, reg(gid, fmt.Sprintf("ra-race-%d-%s-%d", suffix, gid[:8], i), raceIssuer, "https://"+gid[:8]+".example/jwks.json"))
				results <- result{gid, err}
			}(gid, i)
		}
	}
	close(start)
	wg.Wait()
	close(results)
	winners := map[string]int{}
	for r := range results {
		switch {
		case r.err == nil:
			winners[r.gid]++
		case errors.Is(r.err, ErrRemoteApplicationIssuerConflict):
		default:
			t.Fatalf("unexpected error: %v", r.err)
		}
	}
	if len(winners) != 1 {
		t.Fatalf("issuer ended up shared: %v", winners)
	}
	gid, _, _ := ownerOf(raceIssuer)
	if winners[gid] == 0 {
		t.Fatalf("row owner %s is not the winning group %v", gid, winners)
	}
}
