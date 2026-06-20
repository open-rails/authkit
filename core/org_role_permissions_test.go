package core

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"
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
		{"negation tokens do not grant", []string{"app:a", "app:b", "!app:b"}, []string{"app:a", "app:b"}},
	}
	for _, tc := range cases {
		got := get(tc.toks...)
		sort.Strings(tc.want)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestPermissionCoverTokens(t *testing.T) {
	got := permissionCoverTokens("platform:orgs:recover")
	want := []string{
		"platform:orgs:recover",
		"platform:*",
		"platform:*:recover",
		"platform:orgs:*",
		"platform:*:*",
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("permissionCoverTokens=%v want %v", got, want)
	}
}

func TestHasPermissionUsesSingleRoleGrantQuery(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{
		Issuer:      "https://test",
		Permissions: []PermissionDef{{Name: "repo:read"}},
	}, Keyset{}).WithPostgres(pool)

	suffix := time.Now().UnixNano()
	orgSlug := fmt.Sprintf("hot-org-%d", suffix)
	role := "ops"
	user, err := svc.CreateUser(ctx, "", fmt.Sprintf("hotuser%d", suffix))
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, orgSlug)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1`, user.ID)
	})
	if _, err := svc.CreateOrg(ctx, orgSlug); err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	if err := svc.DefineRole(ctx, orgSlug, role); err != nil {
		t.Fatalf("DefineRole: %v", err)
	}
	if err := svc.SetRolePermissions(ctx, orgSlug, role, []string{PermOrgRemoteAppsUpdate, "repo:*"}); err != nil {
		t.Fatalf("SetRolePermissions: %v", err)
	}
	if err := svc.AddMember(ctx, orgSlug, user.ID); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if err := svc.AssignRole(ctx, orgSlug, user.ID, role); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	ok, err := svc.HasPermission(ctx, orgSlug, user.ID, PermOrgRemoteAppsUpdate)
	if err != nil || !ok {
		t.Fatalf("literal HasPermission=(%v,%v), want true,nil", ok, err)
	}
	ok, err = svc.HasPermission(ctx, orgSlug, user.ID, "repo:read")
	if err != nil || !ok {
		t.Fatalf("glob HasPermission=(%v,%v), want true,nil", ok, err)
	}
	ok, err = svc.HasPermission(ctx, orgSlug, user.ID, PermOrgAPIKeysDelete)
	if err != nil || ok {
		t.Fatalf("missing HasPermission=(%v,%v), want false,nil", ok, err)
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
		Permissions: []PermissionDef{
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

func TestValidateGrantRejectsNegationToken(t *testing.T) {
	svc := NewService(Options{
		Permissions: []PermissionDef{{Name: "app:b"}},
	}, Keyset{})

	unknown, offending, err := svc.ValidateGrant(context.Background(), "org", "actor", []string{"!app:b"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(unknown) != 1 || unknown[0] != "!app:b" {
		t.Fatalf("unknown=%v, want [!app:b]", unknown)
	}
	if len(offending) != 0 {
		t.Fatalf("offending=%v, want none", offending)
	}
}
