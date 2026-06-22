package core

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"
)

// TestOwnerGrantTokens proves the owner apex grant set is DERIVED from the app's
// declared catalog (#101): OrgOwnerGrant (org:*) first, then one <ns>:* glob per
// additional app resource namespace, sorted. org:-namespace app perms fold into
// org:*, platform: is excluded (no org role reaches the platform layer), and names
// without a namespace are ignored.
func TestOwnerGrantTokens(t *testing.T) {
	svc := &Service{opts: Options{OwnerOwnsAppResources: true, Permissions: []PermissionDef{
		{Name: "merchant:customers:read"},
		{Name: "merchant:settings:update"},
		{Name: "org:credits:read"},        // org: -> folded into org:*
		{Name: "endpoint:invoke:create"},  // a second app namespace
		{Name: "platform:merchants:read"}, // platform: never owned by an org role
		{Name: "bogus"},                   // no namespace -> ignored
	}}}
	got := svc.ownerGrantTokens()
	want := []string{"org:*", "endpoint:*", "merchant:*"}
	if !slices.Equal(got, want) {
		t.Fatalf("ownerGrantTokens()=%v want %v", got, want)
	}
}

// TestOwnerGrantTokens_DefaultDoesNotOwnAppResources proves the #100 default: with
// OwnerOwnsAppResources unset, the owner apex stays exactly org:* even when the app
// declares resource namespaces — AuthKit imposes no ownership policy unless opted in.
func TestOwnerGrantTokens_DefaultDoesNotOwnAppResources(t *testing.T) {
	svc := &Service{opts: Options{Permissions: []PermissionDef{
		{Name: "merchant:customers:read"},
		{Name: "endpoint:invoke:create"},
	}}}
	if got := svc.ownerGrantTokens(); !slices.Equal(got, []string{OrgOwnerGrant}) {
		t.Fatalf("default ownerGrantTokens()=%v want [%q] (no opt-in)", got, OrgOwnerGrant)
	}
}

// TestOwnerGrantTokens_OptInNoAppPerms: opted in but no app-declared resource
// namespaces => owner apex is still exactly OrgOwnerGrant (the flag adds nothing
// without app namespaces).
func TestOwnerGrantTokens_OptInNoAppPerms(t *testing.T) {
	svc := &Service{opts: Options{OwnerOwnsAppResources: true}}
	if got := svc.ownerGrantTokens(); !slices.Equal(got, []string{OrgOwnerGrant}) {
		t.Fatalf("ownerGrantTokens()=%v want [%q]", got, OrgOwnerGrant)
	}
}

// TestPlatformGrantRejectsAppNamespace proves the platform/org-plane disjointness
// AuthKit #100 requires: a platform role can NEVER hold an app-defined org-scoped
// prefix like merchant:* (or any non-platform: token), keeping the two RBAC layers
// separate even as apps add their own org-scoped namespaces. No DB needed
// (actorAll short-circuits the no-escalation actor lookup).
func TestPlatformGrantRejectsAppNamespace(t *testing.T) {
	svc := NewService(Options{
		Issuer:      "https://test",
		Permissions: []PermissionDef{{Name: "merchant:payments:refund"}},
	}, Keyset{})
	rejects := []string{"merchant:payments:refund", "merchant:*", "org:members:read"}
	unknown, offending, err := svc.ValidatePlatformGrant(context.Background(), "", rejects, true)
	if err != nil {
		t.Fatalf("ValidatePlatformGrant err: %v", err)
	}
	for _, tok := range rejects {
		if !slices.Contains(unknown, tok) {
			t.Fatalf("platform grant must reject non-platform token %q (unknown=%v offending=%v)", tok, unknown, offending)
		}
	}
}

// TestOwnerHoldsAppNamespaceEndToEnd proves the #101 property over real Postgres:
// an org created under a catalog that declares a merchant: namespace gets its
// prebuilt owner role auto-granted merchant:*, so the org owner can exercise
// app-defined merchant permissions with NO explicit grant — and still cannot reach
// the platform layer. This is the guard the OpenRails #554 merchant: namespace
// depends on: owning the org owns the merchant (1:1).
func TestOwnerHoldsAppNamespaceEndToEnd(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{
		Issuer:                "https://test",
		OwnerOwnsAppResources: true,
		Permissions: []PermissionDef{
			{Name: "merchant:customers:read", Description: "read customers"},
			{Name: "merchant:settings:update", Description: "update settings"},
		},
	}, Keyset{}, WithPostgres(pool))

	suffix := time.Now().UnixNano()
	orgSlug := fmt.Sprintf("merchant-org-%d", suffix)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, orgSlug) })
	if _, err := svc.CreateOrg(ctx, orgSlug); err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}

	// The prebuilt owner role is seeded with BOTH org:* and the app's merchant:* glob.
	perms, err := svc.GetRolePermissions(ctx, orgSlug, orgOwnerRole)
	if err != nil {
		t.Fatalf("GetRolePermissions: %v", err)
	}
	if !slices.Contains(perms, OrgOwnerGrant) || !slices.Contains(perms, "merchant:*") {
		t.Fatalf("owner perms=%v, want to contain %q and %q", perms, OrgOwnerGrant, "merchant:*")
	}

	// An owner member effectively holds the concrete app permission, with no grant.
	user, err := svc.CreateUser(ctx, "", fmt.Sprintf("owner%d", suffix))
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1`, user.ID) })
	if err := svc.AddMember(ctx, orgSlug, user.ID); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if err := svc.AssignRole(ctx, orgSlug, user.ID, orgOwnerRole); err != nil {
		t.Fatalf("AssignRole owner: %v", err)
	}
	if ok, err := svc.HasPermission(ctx, orgSlug, user.ID, "merchant:customers:read"); err != nil || !ok {
		t.Fatalf("owner HasPermission(merchant:customers:read)=(%v,%v), want true,nil", ok, err)
	}
	// Owner still cannot reach the separate platform layer.
	if ok, _ := svc.HasPermission(ctx, orgSlug, user.ID, "platform:merchants:read"); ok {
		t.Fatalf("owner must NOT hold platform:merchants:read")
	}
}

// TestEnsureOwnerGrants_Reconcile proves an org created BEFORE a namespace was
// declared gains <ns>:* coverage when the app later calls EnsureOwnerGrants — the
// path apps use after adding a new resource namespace to an existing deployment. (#101)
func TestEnsureOwnerGrants_Reconcile(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	// First boot: app declares no resource namespaces.
	old := NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool))
	suffix := time.Now().UnixNano()
	orgSlug := fmt.Sprintf("recon-org-%d", suffix)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, orgSlug) })
	if _, err := old.CreateOrg(ctx, orgSlug); err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	if perms, _ := old.GetRolePermissions(ctx, orgSlug, orgOwnerRole); slices.Contains(perms, "merchant:*") {
		t.Fatalf("pre-reconcile owner unexpectedly holds merchant:*: %v", perms)
	}
	// Second boot: app now declares a merchant: namespace and reconciles existing orgs.
	upgraded := NewService(Options{Issuer: "https://test", OwnerOwnsAppResources: true, Permissions: []PermissionDef{{Name: "merchant:customers:read"}}}, Keyset{}, WithPostgres(pool))
	if err := upgraded.EnsureOwnerGrants(ctx, orgSlug); err != nil {
		t.Fatalf("EnsureOwnerGrants: %v", err)
	}
	perms, _ := upgraded.GetRolePermissions(ctx, orgSlug, orgOwnerRole)
	if !slices.Contains(perms, OrgOwnerGrant) || !slices.Contains(perms, "merchant:*") {
		t.Fatalf("post-reconcile owner perms=%v, want org:* and merchant:*", perms)
	}
}
