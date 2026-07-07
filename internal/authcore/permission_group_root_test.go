package authcore

import "testing"

func TestIntrinsicRootPermissionsAreValid3Segment(t *testing.T) {
	for _, p := range IntrinsicRootPermissions() {
		if err := ValidatePermission(p); err != nil {
			t.Errorf("intrinsic root perm %q invalid: %v", p, err)
		}
		if PermissionPersona(p) != RootPersona {
			t.Errorf("intrinsic root perm %q is not in the root: namespace", p)
		}
	}
}

func TestBuildSchema_InjectsRootAndValidates(t *testing.T) {
	// An app declaring no root persona gets the intrinsic root injected.
	s, err := BuildSchema(
		PersonaDef{Name: "merchant", Parent: RootPersona,
			Capabilities: PersonaCapabilities{APIKeys: true},
			Roles: []RoleDef{
				{Name: "support", Permissions: []string{"merchant:payments:refund"}},
			}},
	)
	if err != nil {
		t.Fatalf("BuildSchema: %v", err)
	}
	if _, ok := s.Persona(RootPersona); !ok {
		t.Fatalf("root persona not present after BuildSchema")
	}
	// root owner = root:* (the apex).
	owner, _ := s.Role(RootPersona, OwnerRoleName)
	if len(owner.Permissions) != 1 || owner.Permissions[0] != "root:*" {
		t.Errorf("root owner = %v, want [root:*]", owner.Permissions)
	}
	// the merchant persona is a child of root.
	if err := s.ValidateParent("merchant", RootPersona); err != nil {
		t.Errorf("merchant should be allowed under root: %v", err)
	}
}

func TestBuildSchema_AppExtendsRootCatalog(t *testing.T) {
	// doujins-style: extra root moderation roles (root:content:moderate).
	s, err := BuildSchema(
		IntrinsicRootPersona(
			RoleDef{Name: "moderator", Permissions: []string{"root:content:moderate", "root:users:review"}},
		),
	)
	if err != nil {
		t.Fatalf("BuildSchema with extra root roles: %v", err)
	}
	mod, ok := s.Role(RootPersona, "moderator")
	if !ok {
		t.Fatalf("moderator root role missing")
	}
	// A moderator reaches its declared perms but NOT root:* (reach != capability).
	if !s.Can([]GroupAssignment{{Persona: RootPersona, Role: "moderator"}}, nil, "root:content:moderate") {
		t.Errorf("moderator should hold root:content:moderate")
	}
	if s.Can([]GroupAssignment{{Persona: RootPersona, Role: "moderator"}}, nil, "root:users:ban") {
		t.Errorf("moderator (review only) must NOT hold root:users:ban")
	}
	_ = mod
	// A cross-persona perm in a root role must be rejected at declaration.
	if _, err := BuildSchema(IntrinsicRootPersona(RoleDef{Name: "bad", Permissions: []string{"merchant:catalog:update"}})); err == nil {
		t.Errorf("a root role holding merchant: should be rejected (namespace purity)")
	}
}

func TestBuildSchema_MergesHostRootIntoIntrinsicRoot(t *testing.T) {
	s, err := BuildSchema(
		PersonaDef{
			Name: RootPersona,
			Roles: []RoleDef{
				{Name: "operator", Permissions: []string{"root:users:review"}},
			},
			Capabilities: PersonaCapabilities{CustomRoles: true, APIKeys: true},
			Catalog:      []string{"root:users:review"},
		},
		PersonaDef{
			Name: RootPersona,
			Roles: []RoleDef{
				{Name: "auditor", Permissions: []string{"root:resources:read"}},
			},
			Catalog: []string{"root:resources:read"},
		},
		PersonaDef{Name: "merchant", Parent: RootPersona},
	)
	if err != nil {
		t.Fatalf("BuildSchema: %v", err)
	}
	root, ok := s.Persona(RootPersona)
	if !ok {
		t.Fatalf("root persona missing")
	}
	if !root.Capabilities.CustomRoles || !root.Capabilities.APIKeys {
		t.Fatalf("root capabilities = %+v, want custom roles and API keys", root.Capabilities)
	}
	if len(root.Catalog) != 2 || root.Catalog[0] != "root:users:review" || root.Catalog[1] != "root:resources:read" {
		t.Fatalf("root catalog = %v, want [root:users:review root:resources:read]", root.Catalog)
	}
	if _, ok := s.Role(RootPersona, "operator"); !ok {
		t.Fatalf("merged root operator role missing")
	}
	if _, ok := s.Role(RootPersona, "auditor"); !ok {
		t.Fatalf("merged root auditor role missing")
	}
	if _, ok := s.Role(RootPersona, OwnerRoleName); !ok {
		t.Fatalf("intrinsic root owner role missing")
	}
}

func TestBuildSchema_RejectsMultipleRootCapabilityProviders(t *testing.T) {
	if _, err := BuildSchema(
		PersonaDef{Name: RootPersona, Capabilities: PersonaCapabilities{CustomRoles: true}},
		PersonaDef{Name: RootPersona, Capabilities: PersonaCapabilities{APIKeys: true}},
	); err == nil {
		t.Fatalf("BuildSchema accepted multiple root capability providers")
	}
}

func TestBuildSchema_RejectsRootParentOverride(t *testing.T) {
	if _, err := BuildSchema(PersonaDef{Name: RootPersona, Parent: "merchant"}); err == nil {
		t.Fatalf("BuildSchema accepted a parented root persona")
	}
}
