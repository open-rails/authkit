package authcore

import (
	"strings"
	"testing"

	authkit "github.com/open-rails/authkit"
)

func TestValidatePermission(t *testing.T) {
	ok := []string{
		"merchant:catalog:update",
		"root:users:ban",
		"customer:spend-delegations:read",
		"endpoint:self:invoke",
		"org:repo:read",
	}
	for _, p := range ok {
		if err := ValidatePermission(p); err != nil {
			t.Errorf("ValidatePermission(%q) = %v, want nil", p, err)
		}
	}
	bad := []string{
		"",
		"repo:update",              // 2 segments
		"merchant",                 // 1 segment
		"a:b:c:d",                  // 4 segments
		"Merchant:catalog:read",    // uppercase
		"merchant:*:read",          // glob is not a concrete perm
		"merchant:*",               // glob
		"*",                        // bare star
		"merchant::read",           // empty middle segment
		"1merchant:catalog:read",   // leading digit
		"merchant:catalog:up date", // space
	}
	for _, p := range bad {
		if err := ValidatePermission(p); err == nil {
			t.Errorf("ValidatePermission(%q) = nil, want error", p)
		}
	}
}

func TestValidateGrantPattern(t *testing.T) {
	ok := []string{
		"merchant:catalog:update", // concrete
		"merchant:catalog:*",      // resource-wide
		"merchant:*",              // persona-wide (owner grant)
		"root:*",
		"org:repo:read",
	}
	for _, g := range ok {
		if err := ValidateGrantPattern(g); err != nil {
			t.Errorf("ValidateGrantPattern(%q) = %v, want nil", g, err)
		}
	}
	bad := []string{
		"",
		"*",               // bare star
		"*:catalog:read",  // star persona
		"merchant:*:read", // mid-glob not allowed
		"merchant",        // single segment
		"a:b:c:d",         // 4 segments
		"merchant:catalog:read:extra",
	}
	for _, g := range bad {
		if err := ValidateGrantPattern(g); err == nil {
			t.Errorf("ValidateGrantPattern(%q) = nil, want error", g)
		}
	}
}

func TestOwnerGrantAndPersona(t *testing.T) {
	if got := OwnerGrant("merchant"); got != "merchant:*" {
		t.Errorf("OwnerGrant = %q, want merchant:*", got)
	}
	if got := PermissionPersona("org:repo:read"); got != "org" {
		t.Errorf("PermissionPersona = %q, want org", got)
	}
}

// tensorhubSchema is the canonical deep schema used across tests:
// root -> org -> {repo}, org allows custom roles, repo is fixed.
func tensorhubSchema(t *testing.T) *GroupSchema {
	t.Helper()
	s, err := NewGroupSchema(
		PersonaDef{
			Name: RootPersona,
			Roles: []RoleDef{
				{Name: "moderator", Permissions: []string{"root:orgs:delete"}},
			},
		},
		PersonaDef{
			Name:             "org",
			AllowedParents:   []string{RootPersona},
			AllowCustomRoles: true,
			Routes:           ManagementProfile{MemberAssignment: true, CustomRoleCreation: true, APIKeyMinting: true},
			Roles: []RoleDef{
				{Name: "member", Permissions: []string{"org:repo:read"}},
				{Name: "billing", Permissions: []string{"org:billing:read", "org:billing:update"}},
			},
		},
		PersonaDef{
			Name:           "repo",
			AllowedParents: []string{"org"},
			Routes:         ManagementProfile{MemberAssignment: true},
			Roles: []RoleDef{
				{Name: "writer", Permissions: []string{"repo:repo:read", "repo:repo:write"}},
			},
		},
	)
	if err != nil {
		t.Fatalf("NewGroupSchema (valid) errored: %v", err)
	}
	return s
}

func TestNewGroupSchema_SeedsOwnerOnly(t *testing.T) {
	s := tensorhubSchema(t)

	// owner injected = <persona>:* for every persona.
	for _, ty := range []string{"root", "org", "repo"} {
		r, ok := s.Role(ty, OwnerRoleName)
		if !ok {
			t.Fatalf("persona %q missing seeded owner role", ty)
		}
		if len(r.Permissions) != 1 || r.Permissions[0] != OwnerGrant(ty) {
			t.Errorf("persona %q owner perms = %v, want [%s]", ty, r.Permissions, OwnerGrant(ty))
		}
	}
	// app-declared roles survive.
	if _, ok := s.Role("org", "billing"); !ok {
		t.Errorf("org missing declared billing role")
	}
}

func TestNewGroupSchema_Rejections(t *testing.T) {
	cases := []struct {
		name  string
		types []PersonaDef
		want  string // substring of the expected error
	}{
		{
			name:  "no root",
			types: []PersonaDef{{Name: "org", AllowedParents: []string{"root"}}},
			want:  "no root persona declared",
		},
		{
			name: "parentless not named root",
			types: []PersonaDef{
				{Name: "platform"}, // parentless but wrong name
			},
			want: "must be named",
		},
		{
			name: "two roots",
			types: []PersonaDef{
				{Name: "root"},
				{Name: "other"}, // also parentless
			},
			want: "exactly one root",
		},
		{
			name: "cross-persona grant",
			types: []PersonaDef{
				{Name: "root"},
				{Name: "org", AllowedParents: []string{"root"}, Roles: []RoleDef{
					{Name: "x", Permissions: []string{"repo:repo:read"}}, // repo: in an org role
				}},
			},
			want: "cross-persona",
		},
		{
			name: "owner override wrong perms",
			types: []PersonaDef{
				{Name: "root"},
				{Name: "org", AllowedParents: []string{"root"}, Roles: []RoleDef{
					{Name: "owner", Permissions: []string{"org:billing:read"}}, // not org:*
				}},
			},
			want: "must hold exactly",
		},
		{
			name: "undeclared parent",
			types: []PersonaDef{
				{Name: "root"},
				{Name: "repo", AllowedParents: []string{"org"}}, // org not declared
			},
			want: "not a declared persona",
		},
		{
			name: "custom-role route without capability",
			types: []PersonaDef{
				{Name: "root"},
				{Name: "org", AllowedParents: []string{"root"}, Routes: ManagementProfile{CustomRoleCreation: true}},
			},
			want: "requires AllowCustomRoles",
		},
		{
			name: "containment cycle",
			types: []PersonaDef{
				{Name: "root"},
				{Name: "a", AllowedParents: []string{"root", "b"}},
				{Name: "b", AllowedParents: []string{"a"}},
			},
			want: "cycle",
		},
		{
			name: "bad persona name",
			types: []PersonaDef{
				{Name: "root"},
				{Name: "Merchant", AllowedParents: []string{"root"}},
			},
			want: "name must match",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewGroupSchema(tc.types...)
			if err == nil {
				t.Fatalf("NewGroupSchema = nil error, want error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

func TestValidateGroupInstanceSlug(t *testing.T) {
	if err := validateGroupInstanceSlug("merchant", "acme-1"); err != nil {
		t.Fatalf("valid resource slug rejected: %v", err)
	}
	if err := validateGroupInstanceSlug(RootPersona, ""); err != nil {
		t.Fatalf("root group without resource slug rejected: %v", err)
	}
	if err := validateGroupInstanceSlug(RootPersona, "root"); err == nil {
		t.Fatal("root group resource slug accepted, want error")
	}

	bad := []string{"", "Acme", "has space", "has/slash", "ends-", "-starts"}
	for _, slug := range bad {
		if err := validateGroupInstanceSlug("merchant", slug); err == nil {
			t.Errorf("validateGroupInstanceSlug(%q) = nil, want error", slug)
		}
	}
}

func TestValidateParent(t *testing.T) {
	s := tensorhubSchema(t)
	cases := []struct {
		child, parent string
		wantErr       bool
	}{
		{"root", "", false},     // root is parentless
		{"root", "org", true},   // root may not have a parent
		{"org", "root", false},  // org under root: ok
		{"org", "", true},       // non-root needs a parent
		{"repo", "org", false},  // repo under org: ok
		{"repo", "root", true},  // root -> repo impossible
		{"repo", "", true},      // repo needs a parent
		{"repo", "repo", true},  // repo under repo: not allowed
		{"ghost", "root", true}, // unknown child
		{"repo", "ghost", true}, // unknown parent
	}
	for _, tc := range cases {
		err := s.ValidateParent(tc.child, tc.parent)
		if (err != nil) != tc.wantErr {
			t.Errorf("ValidateParent(%q,%q) err=%v, wantErr=%v", tc.child, tc.parent, err, tc.wantErr)
		}
	}
}

// The owner grant must cover its whole namespace and nothing outside it — the
// reach != capability invariant, exercised through the real matcher.
func TestOwnerGrantCoverageIsNamespacePure(t *testing.T) {
	s := tensorhubSchema(t)
	org, _ := s.Role("org", OwnerRoleName)
	grant := org.Permissions[0] // org:*
	covers := func(perm string) bool { return authkit.PermMatches(grant, perm) }
	if !covers("org:repo:read") || !covers("org:billing:update") {
		t.Errorf("org:* should cover its own namespace")
	}
	if covers("root:users:ban") || covers("repo:repo:write") || covers("customer:balance:read") {
		t.Errorf("org:* must NOT reach another persona (reach != capability)")
	}
}
