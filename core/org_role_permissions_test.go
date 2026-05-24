package core

import (
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
	for _, p := range []string{"org:roles:manage", "org:read", "org:tokens:manage"} {
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
	for _, want := range []string{PermOrgRolesManage, PermOrgMembersManage, PermOrgTokensManage, PermOrgRead} {
		if !names[want] {
			t.Errorf("base permission %q missing", want)
		}
	}
}
