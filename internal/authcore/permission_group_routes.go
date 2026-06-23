package authcore

// Route-surface generation (#111): the auto-generated management routes are
// DERIVED from each configured group persona's management profile. Public routes
// and permission strings call that configured name the persona: a `merchant` persona
// emits `/merchant/:resource_slug/...` routes gated by `merchant:<area>:<action>`.
// A disabled capability emits NO route, so calling it 404s, which is stronger
// than a runtime 403. Group ids never appear in a path.

// Built-in per-persona group-management permissions (authkit-provisioned in
// every persona's catalog). All are 3-segment <persona>:<area>:<action>. The owner
// role (=<persona>:*) covers them all; an app may grant them to other roles.
func PermMembersManage(t string) string    { return t + ":members:manage" }
func PermMembersRead(t string) string      { return t + ":members:read" }
func PermRolesManage(t string) string      { return t + ":roles:manage" }
func PermRolesRead(t string) string        { return t + ":roles:read" }
func PermAPIKeysManage(t string) string    { return t + ":api-keys:manage" }
func PermAPIKeysRead(t string) string      { return t + ":api-keys:read" }
func PermRemoteAppsManage(t string) string { return t + ":remote-apps:manage" }
func PermRemoteAppsRead(t string) string   { return t + ":remote-apps:read" }
func PermInvitesManage(t string) string    { return t + ":invites:manage" }
func PermInvitesRead(t string) string      { return t + ":invites:read" }

// GeneratedRoute is one auto-generated management endpoint: addressed by the
// RESOURCE's own id (:resource_slug), gated by Perm (a concrete <persona>:<res>:<act>).
type GeneratedRoute struct {
	Persona string
	Method  string
	Path    string // e.g. /merchant/:resource_slug/members
	Perm    string
}

// GeneratedRoutes returns the full management surface implied by the schema's
// per-persona management profiles. The HTTP layer mounts exactly these; anything
// a profile disables is simply absent (→ 404). Reads gate on <area>:read;
// mutations on the matching <area>:manage built-in.
func (s *GroupSchema) GeneratedRoutes() []GeneratedRoute {
	var out []GeneratedRoute
	for _, persona := range s.Personas() {
		td, _ := s.Persona(persona)
		base := "/" + persona + "/:resource_slug"
		p := td.Routes

		if p.MemberAssignment {
			rd, mg := PermMembersRead(persona), PermMembersManage(persona)
			out = append(out,
				GeneratedRoute{persona, "GET", base + "/members", rd},
				GeneratedRoute{persona, "POST", base + "/members", mg},
				GeneratedRoute{persona, "DELETE", base + "/members/:user", mg},
				GeneratedRoute{persona, "PUT", base + "/members/:user/roles/:role", mg},
			)
		}
		// Listing the catalog is always available; defining custom roles only when on.
		out = append(out, GeneratedRoute{persona, "GET", base + "/roles", PermRolesRead(persona)})
		if p.CustomRoleCreation {
			mg := PermRolesManage(persona)
			out = append(out,
				GeneratedRoute{persona, "POST", base + "/roles", mg},
				GeneratedRoute{persona, "DELETE", base + "/roles/:role", mg},
			)
		}
		if p.APIKeyMinting {
			rd, mg := PermAPIKeysRead(persona), PermAPIKeysManage(persona)
			out = append(out,
				GeneratedRoute{persona, "GET", base + "/api-keys", rd},
				GeneratedRoute{persona, "POST", base + "/api-keys", mg},
				GeneratedRoute{persona, "DELETE", base + "/api-keys/:key", mg},
			)
		}
		if p.RemoteAppRegistration {
			rd, mg := PermRemoteAppsRead(persona), PermRemoteAppsManage(persona)
			out = append(out,
				GeneratedRoute{persona, "GET", base + "/remote-applications", rd},
				GeneratedRoute{persona, "POST", base + "/remote-applications", mg},
				GeneratedRoute{persona, "DELETE", base + "/remote-applications/:app", mg},
			)
		}
		if p.Invitation {
			rd, mg := PermInvitesRead(persona), PermInvitesManage(persona)
			out = append(out,
				GeneratedRoute{persona, "POST", base + "/invites", mg},
				GeneratedRoute{persona, "GET", base + "/invites", rd},
				GeneratedRoute{persona, "DELETE", base + "/invites/:invite", mg},
			)
		}
	}
	return out
}
