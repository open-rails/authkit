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

	// tenant-era residue (the perms are now org:*): these exclusions match nothing.
	stale := []string{"*", "!tenant:roles:manage", "!tenant:members:manage"}
	unknown := UnknownRoleTokenNames(stale, catalog)
	if len(unknown) != 2 {
		t.Fatalf("expected 2 unknown tokens, got %v", unknown)
	}

	// The behavioral consequence the guard prevents: with stale exclusions the
	// role DOES hold the management perms.
	eff := EffectivePermsForTokens(stale, catalog)
	if !eff[PermOrgRolesManage] || !eff[PermOrgMembersManage] {
		t.Fatal("precondition: stale exclusions silently expand the role")
	}

	// Correct exclusions: validate clean AND behaviorally narrowed.
	good := []string{"*", "!" + PermOrgRolesManage, "!" + PermOrgMembersManage}
	if u := UnknownRoleTokenNames(good, catalog); len(u) != 0 {
		t.Fatalf("expected no unknown tokens, got %v", u)
	}
	eff = EffectivePermsForTokens(good, catalog)
	if eff[PermOrgRolesManage] || eff[PermOrgMembersManage] {
		t.Fatal("exclusions must remove the management permissions")
	}
	if !eff["app:thing:read"] || !eff[PermOrgRead] {
		t.Fatal("wildcard must still grant the rest of the catalog")
	}
}
