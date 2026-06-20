package core

import (
	"context"
	"reflect"
	"sort"
	"testing"
)

func TestEffectivePermsForTokens(t *testing.T) {
	cat := map[string]bool{"app:a": true, "app:b": true, "org:members:read": true, "org:roles:update": true}
	get := func(toks ...string) []string {
		return sortedKeys(effectivePermsForTokens(toks, cat))
	}
	cases := []struct {
		name string
		toks []string
		want []string
	}{
		{"bare wildcard is invalid", []string{"*"}, []string{}},
		{"namespace wildcard", []string{"org:*"}, []string{"org:members:read", "org:roles:update"}},
		{"read wildcard", []string{"org:*:read"}, []string{"org:members:read"}},
		{"concrete only", []string{"app:a", "org:roles:update"}, []string{"app:a", "org:roles:update"}},
		{"empty", nil, []string{}},
		{"negation tokens are ignored", []string{"app:a", "app:b", "!app:b"}, []string{"app:a", "app:b"}},
	}
	for _, tc := range cases {
		got := get(tc.toks...)
		sort.Strings(tc.want)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestIsReservedPermission(t *testing.T) {
	for _, p := range []string{PermOrgRolesUpdate, PermOrgSettingsRead, PermOrgAPIKeysCreate, PermOrgRemoteAppsUpdate} {
		if !IsReservedPermission(p) {
			t.Errorf("%q should be reserved", p)
		}
	}
	for _, p := range []string{"endpoint:revise", "repo:read", "*"} {
		if IsReservedPermission(p) {
			t.Errorf("%q should NOT be reserved", p)
		}
	}
}

func TestBasePermissionsPresent(t *testing.T) {
	names := map[string]bool{}
	for _, d := range BasePermissions() {
		names[d.Name] = true
	}
	for _, want := range []string{
		PermOrgMembersCreate,
		PermOrgMembersRead,
		PermOrgMembersUpdate,
		PermOrgMembersDelete,
		PermOrgRolesCreate,
		PermOrgRolesRead,
		PermOrgRolesUpdate,
		PermOrgRolesDelete,
		PermOrgAPIKeysCreate,
		PermOrgAPIKeysRead,
		PermOrgAPIKeysDelete,
		PermOrgRemoteAppsCreate,
		PermOrgRemoteAppsRead,
		PermOrgRemoteAppsUpdate,
		PermOrgRemoteAppsDelete,
		PermOrgSettingsRead,
		PermOrgSettingsUpdate,
	} {
		if !names[want] {
			t.Errorf("base permission %q missing", want)
		}
	}
}

// TestValidateGrant_ResourceScopedPrefix covers #46 resource-scoped grants:
// a "<resource>:<action>:<name>" permission is valid when its
// "<resource>:<action>" base is in the catalog (the app interprets <name>).
// Uses actorAll=true so only the catalog/prefix validation runs (no DB).
func TestValidateGrant_ResourceScopedPrefix(t *testing.T) {
	svc := NewService(Options{
		PermissionCatalog: []PermissionDef{
			{Name: "repo:read"}, {Name: "repo:write"}, {Name: "endpoint:invoke"},
		},
	}, Keyset{})
	ctx := context.Background()

	cases := []struct {
		tok         string
		wantUnknown bool
	}{
		{"repo:read", false},             // exact catalog hit
		{"repo:write:my-model", true},    // scoped tokens must be declared explicitly
		{"endpoint:invoke:my-llm", true}, // scoped tokens must be declared explicitly
		{"repo:read:a/b", true},          // scoped tokens must be declared explicitly
		{"repo:bogus", true},             // not in catalog
		{"repo:bogus:x", true},           // scoped base repo:bogus not in catalog
		{"dataset:read:x", true},         // scoped base dataset:read not in catalog
	}
	for _, c := range cases {
		unknown, _, err := svc.ValidateGrant(ctx, "org", "actor", []string{c.tok}, true)
		if err != nil {
			t.Fatalf("%s: ValidateGrant err: %v", c.tok, err)
		}
		if got := len(unknown) > 0; got != c.wantUnknown {
			t.Errorf("%s: unknown=%v, want %v (unknown=%v)", c.tok, got, c.wantUnknown, unknown)
		}
	}
}
