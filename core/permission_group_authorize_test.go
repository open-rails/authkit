package core

import "testing"

func TestResolveGrants_UnionDedupFailClosed(t *testing.T) {
	s := tensorhubSchema(t)
	asg := []GroupAssignment{
		{GroupType: "org", GroupID: "g_org", Roles: []string{"owner"}},   // org:*
		{GroupType: "repo", GroupID: "g_repo", Roles: []string{"writer"}}, // repo:repo:read, repo:repo:write
		{GroupType: "org", GroupID: "g_org", Roles: []string{"owner"}},    // duplicate -> deduped
		{GroupType: "ghost", GroupID: "g_x", Roles: []string{"owner"}},    // unknown type -> nothing
		{GroupType: "repo", GroupID: "g_repo", Roles: []string{"nope"}},   // unknown role -> nothing
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
	orgOwner := []GroupAssignment{{GroupType: "org", GroupID: "g_org", Roles: []string{"owner"}}}

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
	repoColl := []GroupAssignment{{GroupType: "repo", GroupID: "g_repo", Roles: []string{"writer"}}}
	if !s.Can(repoColl, nil, "repo:repo:write") {
		t.Errorf("repo writer should cover repo:repo:write")
	}
	if s.Can(repoColl, nil, "org:repo:read") {
		t.Errorf("a repo collaborator must NOT hold any org:-scoped perm")
	}
}

func TestCan_RootIsModerationOnly(t *testing.T) {
	s := tensorhubSchema(t)
	// root owner = root:* (super-admin reach) — covers root: perms only.
	rootOwner := []GroupAssignment{{GroupType: "root", GroupID: "g_root", Roles: []string{"owner"}}}
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
	s := tensorhubSchema(t) // org has AllowCustomRoles=true; repo does not
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
	orgCustom := []GroupAssignment{{GroupType: "org", GroupID: "g_org", Roles: []string{"auditor"}}}
	if !s.Can(orgCustom, custom, "org:billing:read") {
		t.Errorf("custom org role should grant org:billing:read")
	}
	// repo disallows custom roles -> a non-catalog role contributes nothing.
	repoCustom := []GroupAssignment{{GroupType: "repo", GroupID: "g_repo", Roles: []string{"auditor"}}}
	if s.Can(repoCustom, custom, "repo:repo:read") {
		t.Errorf("repo disallows custom roles; the custom 'auditor' must be ignored")
	}
	// nil resolver is safe even for a custom-capable type.
	if s.Can(orgCustom, nil, "org:billing:read") {
		t.Errorf("with no resolver, an unknown role grants nothing")
	}
}
