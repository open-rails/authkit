package core

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

func jsonEqual(t *testing.T, a, b json.RawMessage) bool {
	t.Helper()
	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
}

// TestRemoteApplicationPolymorphicMembership proves a remote_application holds a
// org role via the SAME machinery as a user (#74): assign -> resolve ->
// remove, all through org_memberships/org_roles.
func TestRemoteApplicationPolymorphicMembership(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	const tslug = "poly-org"
	const aslug = "poly-app"
	const iss = "https://poly.example/iss"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, aslug)
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, tslug)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, aslug)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, tslug)
	})

	if _, err := svc.CreateOrg(ctx, tslug); err != nil {
		t.Fatalf("create org: %v", err)
	}
	if err := svc.DefineRole(ctx, tslug, "catalog-admin"); err != nil {
		t.Fatalf("define role: %v", err)
	}
	ra, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{Slug: aslug, Issuer: iss, JWKSURI: "https://poly.example/jwks.json", Enabled: true})
	if err != nil {
		t.Fatalf("create remote_application: %v", err)
	}

	// Assign the remote_app the role on the org.
	if err := svc.AddRemoteApplicationMember(ctx, tslug, ra.ID, "catalog-admin"); err != nil {
		t.Fatalf("add member: %v", err)
	}
	role, err := svc.RemoteApplicationOrgRole(ctx, tslug, ra.ID)
	if err != nil || role != "catalog-admin" {
		t.Fatalf("role=%q err=%v, want catalog-admin", role, err)
	}

	// The polymorphic resolution (verifier path) surfaces the same membership.
	memberships, err := svc.RemoteApplicationOrgRoles(ctx, ra.ID)
	if err != nil {
		t.Fatalf("resolve roles: %v", err)
	}
	found := false
	for _, m := range memberships {
		if m.Org == tslug {
			for _, r := range m.Roles {
				if r == "catalog-admin" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("remote_app role not resolved via polymorphic membership: %+v", memberships)
	}

	// A user membership in the SAME org is independent (different member_kind).
	if err := svc.RemoveRemoteApplicationMember(ctx, tslug, ra.ID); err != nil {
		t.Fatalf("remove member: %v", err)
	}
	if _, err := svc.RemoteApplicationOrgRole(ctx, tslug, ra.ID); err != ErrNotOrgMember {
		t.Fatalf("after remove err=%v, want ErrNotOrgMember", err)
	}
}

// TestRemoteAppAttributeDefRegistry exercises the REFERENCE-mode registry (#75):
// register -> resolve (by version + latest) -> list -> delete, with the
// definition stored OPAQUELY.
func TestRemoteAppAttributeDefRegistry(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	const aslug = "attrdef-app"
	const iss = "https://attrdef.example/iss"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, aslug)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, aslug) })

	ra, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{Slug: aslug, Issuer: iss, JWKSURI: "https://attrdef.example/jwks.json", Enabled: true})
	if err != nil {
		t.Fatalf("create remote_application: %v", err)
	}

	def1 := json.RawMessage(`{"endpoints":["marco-polo"],"caps":["5h/$0.20"]}`)
	if _, err := svc.RegisterRemoteAppAttributeDef(ctx, ra.ID, "tier-1", 1, def1); err != nil {
		t.Fatalf("register v1: %v", err)
	}
	def2 := json.RawMessage(`{"endpoints":["marco-polo","stable-diffusion"],"caps":["7d/$1.40"]}`)
	if _, err := svc.RegisterRemoteAppAttributeDef(ctx, ra.ID, "tier-1", 2, def2); err != nil {
		t.Fatalf("register v2: %v", err)
	}

	// Resolve explicit version (jsonb re-serializes, so compare semantically).
	got1, err := svc.ResolveRemoteAppAttributeDef(ctx, ra.ID, "tier-1", 1)
	if err != nil || !jsonEqual(t, got1.Definition, def1) {
		t.Fatalf("resolve v1 mismatch: %s err=%v", got1.Definition, err)
	}
	// Resolve latest (version <= 0).
	gotLatest, err := svc.ResolveRemoteAppAttributeDef(ctx, ra.ID, "tier-1", 0)
	if err != nil || gotLatest.Version != 2 || !jsonEqual(t, gotLatest.Definition, def2) {
		t.Fatalf("resolve latest mismatch: %+v err=%v", gotLatest, err)
	}

	// List returns both versions.
	all, err := svc.ListRemoteAppAttributeDefs(ctx, ra.ID)
	if err != nil || len(all) != 2 {
		t.Fatalf("list len=%d err=%v, want 2", len(all), err)
	}

	// Invalid (non-JSON) definition rejected.
	if _, err := svc.RegisterRemoteAppAttributeDef(ctx, ra.ID, "bad", 1, json.RawMessage(`not json`)); err != ErrInvalidAttributeDef {
		t.Fatalf("bad def err=%v, want ErrInvalidAttributeDef", err)
	}

	// Delete removes all versions.
	if err := svc.DeleteRemoteAppAttributeDef(ctx, ra.ID, "tier-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := svc.ResolveRemoteAppAttributeDef(ctx, ra.ID, "tier-1", 0); err != ErrAttributeDefNotFound {
		t.Fatalf("after delete err=%v, want ErrAttributeDefNotFound", err)
	}
}
