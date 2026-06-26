package authcore

import "testing"

func TestResolveGrants_UnionDedupFailClosed(t *testing.T) {
	s := tensorhubSchema(t)
	asg := []GroupAssignment{
		{Persona: "org", PermissionGroupID: "g_org", Roles: []string{"owner"}},    // org:*
		{Persona: "repo", PermissionGroupID: "g_repo", Roles: []string{"writer"}}, // repo:repo:read, repo:repo:write
		{Persona: "org", PermissionGroupID: "g_org", Roles: []string{"owner"}},    // duplicate -> deduped
		{Persona: "ghost", PermissionGroupID: "g_x", Roles: []string{"owner"}},    // unknown persona -> nothing
		{Persona: "repo", PermissionGroupID: "g_repo", Roles: []string{"nope"}},   // unknown role -> nothing
	}
	got := s.ResolveGrants(asg, nil)
	want := map[string]bool{"org:*": true, "repo:repo:read": true, "repo:repo:write": true}
	if len(got) != len(want) {
		t.Fatalf("ResolveGrants = %v, want keys %v", got, want)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected grant %q in %v", g, got)
		}
	}
}

// The additive walk-up: an org-level owner assignment authorizes an org-scoped
// resource perm (org:repo:read) — the engine checks org:repo:read against the
// org-level assignment. It does NOT confer repo:repo:* (a different persona); a
// single-repo collaborator must be assigned IN the repo group. reach != capability.
func TestCan_WalkUpAndNamespacePurity(t *testing.T) {
	s := tensorhubSchema(t)
	orgOwner := []GroupAssignment{{Persona: "org", PermissionGroupID: "g_org", Roles: []string{"owner"}}}

	if !s.Can(orgOwner, nil, "org:repo:read") {
		t.Errorf("org owner (org:*) should cover org:repo:read (walk-up)")
	}
	if !s.Can(orgOwner, nil, "org:billing:update") {
		t.Errorf("org owner (org:*) should cover org:billing:update")
	}
	// org:* must NOT reach the repo persona, root, or another app's persona.
	for _, p := range []string{"repo:repo:write", "root:users:ban", "customer:balance:read"} {
		if s.Can(orgOwner, nil, p) {
			t.Errorf("org owner (org:*) must NOT cover %q (reach != capability)", p)
		}
	}

	// A repo collaborator covers repo perms but nothing org-scoped.
	repoColl := []GroupAssignment{{Persona: "repo", PermissionGroupID: "g_repo", Roles: []string{"writer"}}}
	if !s.Can(repoColl, nil, "repo:repo:write") {
		t.Errorf("repo writer should cover repo:repo:write")
	}
	if s.Can(repoColl, nil, "org:repo:read") {
		t.Errorf("a repo collaborator must NOT hold any org:-scoped perm")
	}
}

func TestCan_RootIsModerationOnly(t *testing.T) {
	s := tensorhubSchema(t)
	// root owner = root:* — covers root: perms only.
	rootOwner := []GroupAssignment{{Persona: "root", PermissionGroupID: "g_root", Roles: []string{"owner"}}}
	if !s.Can(rootOwner, nil, "root:users:ban") || !s.Can(rootOwner, nil, "root:orgs:delete") {
		t.Errorf("root owner (root:*) should cover root: perms")
	}
	// Widest REACH, narrowest CAPABILITY: root:* cannot reach an org/repo internal.
	for _, p := range []string{"org:repo:read", "repo:repo:write", "merchant:catalog:update"} {
		if s.Can(rootOwner, nil, p) {
			t.Errorf("root:* must NOT cover %q — root is moderation-only", p)
		}
	}
}

func TestResolveGrants_CustomRoles(t *testing.T) {
	s := tensorhubSchema(t) // org has CustomRoles=true; repo does not
	custom := func(groupID, role string) ([]string, bool) {
		if groupID == "g_org" && role == "auditor" {
			return []string{"org:billing:read"}, true
		}
		if groupID == "g_repo" && role == "auditor" {
			return []string{"repo:repo:read"}, true // must be IGNORED: repo disallows custom roles
		}
		return nil, false
	}
	// org allows custom roles -> the custom "auditor" resolves.
	orgCustom := []GroupAssignment{{Persona: "org", PermissionGroupID: "g_org", Roles: []string{"auditor"}}}
	if !s.Can(orgCustom, custom, "org:billing:read") {
		t.Errorf("custom org role should grant org:billing:read")
	}
	// repo disallows custom roles -> a non-catalog role contributes nothing.
	repoCustom := []GroupAssignment{{Persona: "repo", PermissionGroupID: "g_repo", Roles: []string{"auditor"}}}
	if s.Can(repoCustom, custom, "repo:repo:read") {
		t.Errorf("repo disallows custom roles; the custom 'auditor' must be ignored")
	}
	// nil resolver is safe even for a custom-capable persona.
	if s.Can(orgCustom, nil, "org:billing:read") {
		t.Errorf("with no resolver, an unknown role grants nothing")
	}
}

func TestCan_FailClosedForSchemaDrift(t *testing.T) {
	assignment := []GroupAssignment{{Persona: "org", PermissionGroupID: "g_org", Roles: []string{"billing"}}}

	removedRole := mustAuthzSchema(t,
		PersonaDef{Name: "org", Parent: RootPersona},
	)
	if removedRole.Can(assignment, nil, "org:billing:read") {
		t.Fatalf("removed catalog role must grant nothing")
	}

	renamedRole := mustAuthzSchema(t,
		PersonaDef{
			Name:   "org",
			Parent: RootPersona,
			Roles:  []RoleDef{{Name: "finance", Permissions: []string{"org:billing:read"}}},
		},
	)
	if renamedRole.Can(assignment, nil, "org:billing:read") {
		t.Fatalf("renamed role's old assignment name must grant nothing")
	}

	removedPermission := mustAuthzSchema(t,
		PersonaDef{
			Name:   "org",
			Parent: RootPersona,
			Roles:  []RoleDef{{Name: "billing", Permissions: []string{"org:billing:read"}}},
		},
	)
	if removedPermission.Can(assignment, nil, "org:billing:update") {
		t.Fatalf("removed permission must grant nothing")
	}
	if !removedPermission.Can(assignment, nil, "org:billing:read") {
		t.Fatalf("remaining permission should still grant")
	}

	customResolver := func(groupID, role string) ([]string, bool) {
		if groupID == "g_org" && role == "billing" {
			return []string{"org:billing:read"}, true
		}
		return nil, false
	}
	customDisabled := mustAuthzSchema(t,
		PersonaDef{Name: "org", Parent: RootPersona},
	)
	if customDisabled.Can(assignment, customResolver, "org:billing:read") {
		t.Fatalf("custom role on a custom-roles-disabled persona must grant nothing")
	}

	reusedName := mustAuthzSchema(t,
		PersonaDef{
			Name:   "org",
			Parent: RootPersona,
			Roles:  []RoleDef{{Name: "billing", Permissions: []string{"org:danger:write"}}},
		},
	)
	if !reusedName.Can(assignment, nil, "org:danger:write") {
		t.Fatalf("reused role name should reactivate stale assignments; docs must warn operators")
	}
}

func mustAuthzSchema(t *testing.T, personas ...PersonaDef) *GroupSchema {
	t.Helper()
	s, err := BuildSchema(personas...)
	if err != nil {
		t.Fatalf("BuildSchema: %v", err)
	}
	return s
}
