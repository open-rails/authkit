package core

import "testing"

func TestIntrinsicRootPermissionsAreValid3Segment(t *testing.T) {
	for _, p := range IntrinsicRootPermissions() {
		if err := ValidatePermission(p); err != nil {
			t.Errorf("intrinsic root perm %q invalid: %v", p, err)
		}
		if PermissionPersona(p) != RootType {
			t.Errorf("intrinsic root perm %q is not in the root: namespace", p)
		}
	}
}

func TestBuildSchema_InjectsRootAndValidates(t *testing.T) {
	// An app declaring no root type gets the intrinsic root injected.
	s, err := BuildSchema(
		GroupTypeDef{Name: "merchant", AllowedParents: []string{RootType},
			Routes: ManagementProfile{MemberAssignment: true, APIKeyMinting: true},
			Roles: []RoleDef{
				{Name: "support", Permissions: []string{"merchant:payments:refund"}},
			}},
	)
	if err != nil {
		t.Fatalf("BuildSchema: %v", err)
	}
	if _, ok := s.Type(RootType); !ok {
		t.Fatalf("root type not present after BuildSchema")
	}
	// root owner = root:* (super-admin reach), moderation-only.
	owner, _ := s.Role(RootType, OwnerRoleName)
	if len(owner.Permissions) != 1 || owner.Permissions[0] != "root:*" {
		t.Errorf("root owner = %v, want [root:*]", owner.Permissions)
	}
	if _, ok := s.Role(RootType, SuperAdminRoleName); !ok {
		t.Errorf("root missing super-admin role")
	}
	// the merchant type is a child of root.
	if err := s.ValidateParent("merchant", RootType); err != nil {
		t.Errorf("merchant should be allowed under root: %v", err)
	}
}

func TestBuildSchema_AppExtendsRootCatalog(t *testing.T) {
	// doujins-style: extra root moderation roles (root:content:moderate).
	s, err := BuildSchema(
		IntrinsicRootType(
			RoleDef{Name: "moderator", Permissions: []string{"root:content:moderate", "root:users:suspend"}},
		),
	)
	if err != nil {
		t.Fatalf("BuildSchema with extra root roles: %v", err)
	}
	mod, ok := s.Role(RootType, "moderator")
	if !ok {
		t.Fatalf("moderator root role missing")
	}
	// A moderator reaches its declared perms but NOT root:* (reach != capability).
	if !s.Can([]GroupAssignment{{GroupType: RootType, Roles: []string{"moderator"}}}, nil, "root:content:moderate") {
		t.Errorf("moderator should hold root:content:moderate")
	}
	if s.Can([]GroupAssignment{{GroupType: RootType, Roles: []string{"moderator"}}}, nil, "root:users:ban") {
		t.Errorf("moderator (suspend only) must NOT hold root:users:ban")
	}
	_ = mod
	// A cross-persona perm in a root role must be rejected at declaration.
	if _, err := BuildSchema(IntrinsicRootType(RoleDef{Name: "bad", Permissions: []string{"merchant:catalog:update"}})); err == nil {
		t.Errorf("a root role holding merchant: should be rejected (namespace purity)")
	}
}
