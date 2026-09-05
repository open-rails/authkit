package embedded

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
)

// TestPersonaRequireConsent covers the #193 per-persona join policy accessor and
// the root-defaults-to-instant rule (no DB).
func TestPersonaRequireConsent(t *testing.T) {
	gs, err := BuildSchema(
		IntrinsicRootPersona(), // root: RequireConsent defaults to false (instant)
		PersonaDef{Name: "team", Parent: RootPersona, RequireConsent: true},
		PersonaDef{Name: "repo", Parent: RootPersona}, // omitted => false
	)
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	if gs.RequireConsent(RootPersona) {
		t.Fatalf("root must default to instant (RequireConsent=false)")
	}
	if !gs.RequireConsent("team") {
		t.Fatalf("team should require consent")
	}
	if gs.RequireConsent("repo") {
		t.Fatalf("repo should be instant (RequireConsent unset)")
	}
	if gs.RequireConsent("nonexistent") {
		t.Fatalf("unknown persona must default to false")
	}
}

// TestLastOwnerGuard_DB: an actor-checked removal of the sole owner is refused
// (it would orphan the group), so authority never silently vanishes.
func TestLastOwnerGuard_DB(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	if _, err := svc.EnsureRootGroup(ctx); err != nil {
		t.Fatalf("ensure root group: %v", err)
	}
	var owner string
	if err := pool.QueryRow(ctx, `INSERT INTO profiles.users (username) VALUES ($1) RETURNING id::text`,
		fmt.Sprintf("last-owner-%d", time.Now().UnixNano())).Scan(&owner); err != nil {
		t.Fatalf("create owner: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, owner) })
	if err := svc.AssignGroupRoleGenesis(ctx, authkit.RootGroup(), authkit.UserSubject(owner), OwnerRoleName); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	if err := svc.RemoveGroupSubjectAs(ctx, owner, authkit.RootGroup(), authkit.UserSubject(owner)); !errors.Is(err, ErrCannotRemoveLastAdminRole) {
		t.Fatalf("remove sole owner: got %v, want ErrCannotRemoveLastAdminRole", err)
	}
	ok, err := svc.Can(ctx, authkit.UserSubject(owner), authkit.RootGroup(), PermRootUsersBan)
	if err != nil || !ok {
		t.Fatalf("sole owner must keep authority after a refused removal: ok=%v err=%v", ok, err)
	}
}
