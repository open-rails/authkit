package core

import (
	"context"
	"reflect"
	"sort"
	"testing"
)

func TestEffectivePermsForTokens(t *testing.T) {
	cat := map[string]bool{"a": true, "b": true, "c": true, "org:read": true}
	get := func(toks ...string) []string {
		return sortedKeys(effectivePermsForTokens(toks, cat))
	}
	cases := []struct {
		name string
		toks []string
		want []string
	}{
		{"wildcard = all catalog", []string{"*"}, []string{"a", "b", "c", "org:read"}},
		{"wildcard minus exclusion", []string{"*", "!b"}, []string{"a", "c", "org:read"}},
		{"concrete only", []string{"a", "c"}, []string{"a", "c"}},
		{"empty", nil, []string{}},
		{"exclusion without wildcard removes from positives", []string{"a", "b", "!b"}, []string{"a"}},
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
	for _, p := range []string{"org:roles:manage", "org:read", "org:service_tokens:manage", "org:remote_applications:manage"} {
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
	for _, want := range []string{PermOrgRolesManage, PermOrgMembersManage, PermOrgTokensManage, PermOrgRemoteAppsManage, PermOrgRead} {
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
		{"repo:read", false},              // exact catalog hit
		{"repo:write:my-model", false},    // scoped; base repo:write in catalog
		{"endpoint:invoke:my-llm", false}, // scoped; base endpoint:invoke in catalog
		{"repo:read:a/b", false},          // name with a slash is fine
		{"repo:bogus", true},              // not in catalog
		{"repo:bogus:x", true},            // scoped base repo:bogus not in catalog
		{"dataset:read:x", true},          // scoped base dataset:read not in catalog
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
