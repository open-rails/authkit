package core

// Route-surface generation (#111): the auto-generated per-persona management
// routes are DERIVED from each type's management profile — "the route surface IS
// the capability spec" (a disabled capability emits NO route, so calling it 404s,
// which is stronger than a runtime 403). This file computes that surface as data;
// the HTTP layer mounts a handler per spec (resolving (persona, resource-id) ->
// group via resource_ref, then gating on Perm). Group ids never appear in a path.

// Built-in per-type group-management permissions (authkit-provisioned in every
// type's catalog). All are 3-segment <persona>:<area>:<action>. The owner role
// (=<type>:*) covers them all; an app may grant them to other roles.
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
// RESOURCE's own id (:resource-id), gated by Perm (a concrete <persona>:<res>:<act>).
type GeneratedRoute struct {
	Persona string
	Method  string
	Path    string // e.g. /:persona/:resource-id/members  (with :persona bound to Persona)
	Perm    string
}

// GeneratedRoutes returns the full management surface implied by the schema's
// per-type management profiles. The HTTP layer mounts exactly these; anything a
// profile disables is simply absent (→ 404). Reads gate on <area>:read; mutations
// on the matching <area>:manage built-in.
func (s *GroupSchema) GeneratedRoutes() []GeneratedRoute {
	var out []GeneratedRoute
	for _, typeName := range s.Types() {
		td, _ := s.Type(typeName)
		base := "/" + typeName + "/:resource-id"
		p := td.Routes

		if p.MemberAssignment {
			rd, mg := PermMembersRead(typeName), PermMembersManage(typeName)
			out = append(out,
				GeneratedRoute{typeName, "GET", base + "/members", rd},
				GeneratedRoute{typeName, "POST", base + "/members", mg},
				GeneratedRoute{typeName, "DELETE", base + "/members/:user", mg},
				GeneratedRoute{typeName, "PUT", base + "/members/:user/roles/:role", mg},
				GeneratedRoute{typeName, "DELETE", base + "/members/:user/roles/:role", mg},
			)
		}
		// Listing the catalog is always available; defining custom roles only when on.
		out = append(out, GeneratedRoute{typeName, "GET", base + "/roles", PermRolesRead(typeName)})
		if p.CustomRoleCreation {
			mg := PermRolesManage(typeName)
			out = append(out,
				GeneratedRoute{typeName, "POST", base + "/roles", mg},
				GeneratedRoute{typeName, "DELETE", base + "/roles/:role", mg},
			)
		}
		if p.APIKeyMinting {
			rd, mg := PermAPIKeysRead(typeName), PermAPIKeysManage(typeName)
			out = append(out,
				GeneratedRoute{typeName, "GET", base + "/api-keys", rd},
				GeneratedRoute{typeName, "POST", base + "/api-keys", mg},
				GeneratedRoute{typeName, "DELETE", base + "/api-keys/:key", mg},
			)
		}
		if p.RemoteAppRegistration {
			rd, mg := PermRemoteAppsRead(typeName), PermRemoteAppsManage(typeName)
			out = append(out,
				GeneratedRoute{typeName, "GET", base + "/remote-applications", rd},
				GeneratedRoute{typeName, "POST", base + "/remote-applications", mg},
				GeneratedRoute{typeName, "DELETE", base + "/remote-applications/:app", mg},
			)
		}
		if p.Invitation {
			rd, mg := PermInvitesRead(typeName), PermInvitesManage(typeName)
			out = append(out,
				GeneratedRoute{typeName, "POST", base + "/invites", mg},
				GeneratedRoute{typeName, "GET", base + "/invites", rd},
				GeneratedRoute{typeName, "DELETE", base + "/invites/:invite", mg},
			)
		}
	}
	return out
}
