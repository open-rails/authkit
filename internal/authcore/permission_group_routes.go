package authcore

// Route-surface generation (#111): the auto-generated management routes are
// DERIVED from each configured group persona. Public routes
// and permission strings call that configured name the persona: a `merchant` persona
// emits `/merchant/:instance_slug/...` routes gated by `merchant:<area>:<action>`.
// A disabled capability emits NO route, so calling it 404s, which is stronger
// than a runtime 403. Group ids never appear in a path.

import authkit "github.com/open-rails/authkit"

// Built-in per-persona group-management permissions (authkit-provisioned in
// every persona's catalog). All are 3-segment <persona>:<area>:<action>. The owner
// role (=<persona>:*) covers them all; an app may grant them to other roles.
func PermMembersManage(p authkit.Persona) authkit.Perm {
	return authkit.Perm(string(p) + ":members:manage")
}
func PermMembersRead(p authkit.Persona) authkit.Perm {
	return authkit.Perm(string(p) + ":members:read")
}
func PermRolesManage(p authkit.Persona) authkit.Perm {
	return authkit.Perm(string(p) + ":roles:manage")
}
func PermRolesRead(p authkit.Persona) authkit.Perm { return authkit.Perm(string(p) + ":roles:read") }
func PermCredentialsManage(p authkit.Persona) authkit.Perm {
	return authkit.Perm(string(p) + ":credentials:manage")
}
func PermCredentialsRead(p authkit.Persona) authkit.Perm {
	return authkit.Perm(string(p) + ":credentials:read")
}

// PermSettingsManage gates the group's own settings surface (#264): slug
// rename and display-name changes. Held by the owner via `<persona>:*`;
// grant it to other roles deliberately.
func PermSettingsManage(p authkit.Persona) authkit.Perm {
	return authkit.Perm(string(p) + ":settings:manage")
}

// PermSettingsRead gates reading the group's own identity descriptor (#269):
// GET /<persona>/:instance_slug — id, slug, display name. The read symmetric of
// PermSettingsManage; held by the owner via `<persona>:*`.
func PermSettingsRead(p authkit.Persona) authkit.Perm {
	return authkit.Perm(string(p) + ":settings:read")
}

// GeneratedRoute is one auto-generated management endpoint: addressed by the
// RESOURCE's own id (:instance_slug), gated by Perm (a concrete <persona>:<res>:<act>).
type GeneratedRoute struct {
	Persona authkit.Persona
	Method  string
	Path    string // e.g. /merchant/:instance_slug/members
	Perm    authkit.Perm
}

// GeneratedRoutes returns the full management surface implied by the schema's
// per-persona definition. The HTTP layer mounts exactly these; disabled
// capabilities are simply absent (→ 404). Reads gate on <area>:read;
// mutations on the matching <area>:manage built-in.
func (s *GroupSchema) GeneratedRoutes() []GeneratedRoute {
	var out []GeneratedRoute
	for _, persona := range s.Personas() {
		td, _ := s.Persona(persona)
		base := "/" + string(persona) + "/:instance_slug"
		caps := td.Capabilities
		memberRoutes := persona != RootPersona

		if memberRoutes {
			rd, mg := PermMembersRead(persona), PermMembersManage(persona)
			out = append(out,
				GeneratedRoute{persona, "GET", base + "/members", rd},
				GeneratedRoute{persona, "POST", base + "/members", mg},
				GeneratedRoute{persona, "DELETE", base + "/members/:user", mg},
				GeneratedRoute{persona, "PUT", base + "/members/:user/roles/:role", mg},
				// #264: group settings — slug rename (tombstone-forwarding)
				// and display-name changes. Owner-controlled via the wildcard.
				GeneratedRoute{persona, "PATCH", base, PermSettingsManage(persona)},
				// #269: the instance's own identity descriptor — the read
				// symmetric of the PATCH, and the only place a caller outside
				// the process learns the group's uuid. Creation reports it
				// once; this route is how it stays recoverable (and how an
				// instance created before #269 becomes addressable at all).
				GeneratedRoute{persona, "GET", base, PermSettingsRead(persona)},
			)
		}
		// Listing the role catalog is part of visible role/member management;
		// personas with every management capability off emit no public routes.
		if memberRoutes || caps.CustomRoles {
			out = append(out, GeneratedRoute{persona, "GET", base + "/roles", PermRolesRead(persona)})
		}
		if caps.CustomRoles {
			mg := PermRolesManage(persona)
			out = append(out,
				GeneratedRoute{persona, "POST", base + "/roles", mg},
				GeneratedRoute{persona, "DELETE", base + "/roles/:role", mg},
			)
		}
		if caps.APIKeys {
			rd, mg := PermCredentialsRead(persona), PermCredentialsManage(persona)
			out = append(out,
				GeneratedRoute{persona, "GET", base + "/api-keys", rd},
				GeneratedRoute{persona, "POST", base + "/api-keys", mg},
				GeneratedRoute{persona, "DELETE", base + "/api-keys/:key", mg},
			)
		}
		if caps.RemoteApplications {
			rd, mg := PermCredentialsRead(persona), PermCredentialsManage(persona)
			out = append(out,
				GeneratedRoute{persona, "GET", base + "/remote-applications", rd},
				GeneratedRoute{persona, "POST", base + "/remote-applications", mg},
				GeneratedRoute{persona, "DELETE", base + "/remote-applications/:app", mg},
				// #263: remote-application role assignment — the
				// SubjectKindRemoteApp symmetric of the member-role route.
				GeneratedRoute{persona, "PUT", base + "/remote-applications/:app/roles/:role", mg},
			)
		}
		// Invite-LINK routes (#134): mint / list / revoke a high-entropy invite
		// link. Redemption is NOT here — it is the persona-agnostic POST
		// /invites/redeem (any authenticated user), mounted as a fixed route.
		if memberRoutes {
			rd, mg := PermMembersRead(persona), PermMembersManage(persona)
			out = append(out,
				GeneratedRoute{persona, "POST", base + "/invites/links", mg},
				GeneratedRoute{persona, "GET", base + "/invites/links", rd},
				GeneratedRoute{persona, "DELETE", base + "/invites/links/:link", mg},
			)
		}
	}
	return out
}
