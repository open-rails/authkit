package authcore

import "testing"

func TestGeneratedRoutes_SurfaceMirrorsProfile(t *testing.T) {
	// merchant: members + api-keys, NO custom-roles, NO remote-apps, NO invites.
	// repo: members only.
	s, err := BuildSchema(
		PersonaDef{
			Name: "merchant", AllowedParents: []string{RootPersona},
			Routes: ManagementProfile{MemberAssignment: true, APIKeyMinting: true},
			Roles:  []RoleDef{{Name: "support", Permissions: []string{"merchant:payments:refund"}}},
		},
		PersonaDef{
			Name: "repo", AllowedParents: []string{RootPersona},
			Routes: ManagementProfile{MemberAssignment: true},
		},
	)
	if err != nil {
		t.Fatalf("BuildSchema: %v", err)
	}

	has := func(persona, method, path string) bool {
		for _, r := range s.GeneratedRoutes() {
			if r.Persona == persona && r.Method == method && r.Path == path {
				return true
			}
		}
		return false
	}

	// merchant: members + api-keys present.
	if !has("merchant", "POST", "/merchant/:instance_slug/members") {
		t.Errorf("merchant member-assignment route missing")
	}
	if !has("merchant", "POST", "/merchant/:instance_slug/api-keys") {
		t.Errorf("merchant api-key route missing")
	}
	// merchant: custom-roles OFF -> NO define route (the 404 invariant); GET roles still present.
	if has("merchant", "POST", "/merchant/:instance_slug/roles") {
		t.Errorf("merchant has custom-role-creation OFF; POST /roles must NOT be generated")
	}
	if !has("merchant", "GET", "/merchant/:instance_slug/roles") {
		t.Errorf("listing the role catalog should always be available")
	}
	// merchant: remote-apps + invites OFF -> absent.
	if has("merchant", "POST", "/merchant/:instance_slug/remote-applications") {
		t.Errorf("remote-apps OFF must not be generated")
	}
	if has("merchant", "POST", "/merchant/:instance_slug/invites/links") {
		t.Errorf("invites OFF must not be generated")
	}

	// repo: members present, api-keys absent.
	if !has("repo", "POST", "/repo/:instance_slug/members") {
		t.Errorf("repo member route missing")
	}
	if has("repo", "POST", "/repo/:instance_slug/api-keys") {
		t.Errorf("repo api-keys OFF must not be generated")
	}
}

func TestGeneratedRoutes_GatesAreCorrect(t *testing.T) {
	s, _ := BuildSchema(PersonaDef{
		Name: "org", AllowedParents: []string{RootPersona}, AllowCustomRoles: true,
		Routes: ManagementProfile{MemberAssignment: true, CustomRoleCreation: true, APIKeyMinting: true, RemoteAppRegistration: true, InviteLinks: true},
	})
	want := map[string]string{ // "METHOD path" -> gate perm
		"POST /org/:instance_slug/members":             "org:roles:manage",
		"GET /org/:instance_slug/members":              "org:members:read",
		"POST /org/:instance_slug/roles":               "org:roles:manage",
		"GET /org/:instance_slug/roles":                "org:roles:read",
		"POST /org/:instance_slug/api-keys":            "org:api-keys:manage",
		"POST /org/:instance_slug/remote-applications": "org:remote-apps:manage",
		"POST /org/:instance_slug/invites/links":       "org:invites:manage",
	}
	got := map[string]string{}
	for _, r := range s.GeneratedRoutes() {
		got[r.Method+" "+r.Path] = r.Perm
	}
	for k, perm := range want {
		if got[k] != perm {
			t.Errorf("route %q gate = %q, want %q", k, got[k], perm)
		}
	}
	// Every generated gate is a valid concrete 3-segment perm in the persona namespace.
	for _, r := range s.GeneratedRoutes() {
		if err := ValidatePermission(r.Perm); err != nil {
			t.Errorf("gate %q is not a valid 3-segment perm: %v", r.Perm, err)
		}
		if PermissionPersona(r.Perm) != r.Persona {
			t.Errorf("gate %q is not in persona %q", r.Perm, r.Persona)
		}
	}
}
