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
	if !has("merchant", "POST", "/merchant/:resource-id/members") {
		t.Errorf("merchant member-assignment route missing")
	}
	if !has("merchant", "POST", "/merchant/:resource-id/api-keys") {
		t.Errorf("merchant api-key route missing")
	}
	// merchant: custom-roles OFF -> NO define route (the 404 invariant); GET roles still present.
	if has("merchant", "POST", "/merchant/:resource-id/roles") {
		t.Errorf("merchant has custom-role-creation OFF; POST /roles must NOT be generated")
	}
	if !has("merchant", "GET", "/merchant/:resource-id/roles") {
		t.Errorf("listing the role catalog should always be available")
	}
	// merchant: remote-apps + invites OFF -> absent.
	if has("merchant", "POST", "/merchant/:resource-id/remote-applications") {
		t.Errorf("remote-apps OFF must not be generated")
	}
	if has("merchant", "POST", "/merchant/:resource-id/invites") {
		t.Errorf("invites OFF must not be generated")
	}

	// repo: members present, api-keys absent.
	if !has("repo", "POST", "/repo/:resource-id/members") {
		t.Errorf("repo member route missing")
	}
	if has("repo", "POST", "/repo/:resource-id/api-keys") {
		t.Errorf("repo api-keys OFF must not be generated")
	}
}

func TestGeneratedRoutes_GatesAreCorrect(t *testing.T) {
	s, _ := BuildSchema(PersonaDef{
		Name: "org", AllowedParents: []string{RootPersona}, AllowCustomRoles: true,
		Routes: ManagementProfile{MemberAssignment: true, CustomRoleCreation: true, APIKeyMinting: true, RemoteAppRegistration: true, Invitation: true},
	})
	want := map[string]string{ // "METHOD path" -> gate perm
		"POST /org/:resource-id/members":             "org:members:manage",
		"GET /org/:resource-id/members":              "org:members:read",
		"POST /org/:resource-id/roles":               "org:roles:manage",
		"GET /org/:resource-id/roles":                "org:roles:read",
		"POST /org/:resource-id/api-keys":            "org:api-keys:manage",
		"POST /org/:resource-id/remote-applications": "org:remote-apps:manage",
		"POST /org/:resource-id/invites":             "org:invites:manage",
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
