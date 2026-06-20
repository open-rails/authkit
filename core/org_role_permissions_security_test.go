package core

import "testing"

// TestUnknownExclusionsAreDetectable locks the guard for the 2026-06-10
// incident class: an exclusion naming a permission that does not exist
// subtracts nothing, so the role silently keeps it. UnknownRoleTokenNames
// must surface exactly those tokens.
func TestUnknownExclusionsAreDetectable(t *testing.T) {
	catalog := map[string]bool{}
	for _, p := range BaseReservedPermissions() {
		catalog[p] = true
	}
	catalog["app:thing:read"] = true

	// tenant-era residue plus a bare wildcard: none are valid #95 grant tokens.
	stale := []string{"*", "!tenant:roles:manage", "!tenant:members:manage"}
	unknown := UnknownRoleTokenNames(stale, catalog)
	if len(unknown) != 3 {
		t.Fatalf("expected 3 unknown tokens, got %v", unknown)
	}

	// Invalid tokens grant nothing.
	eff := EffectivePermsForTokens(stale, catalog)
	if len(eff) != 0 {
		t.Fatalf("stale tokens must not grant permissions, got %v", eff)
	}

	// Correct namespace-anchored grant: validate clean AND behaviorally scoped.
	good := []string{OrgOwnerGrant, "app:*"}
	if u := UnknownRoleTokenNames(good, catalog); len(u) != 0 {
		t.Fatalf("expected no unknown tokens, got %v", u)
	}
	eff = EffectivePermsForTokens(good, catalog)
	if !eff["app:thing:read"] || !eff[PermOrgSettingsRead] {
		t.Fatal("wildcard must still grant the rest of the catalog")
	}
}
