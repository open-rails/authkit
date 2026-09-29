package httpapi

import "github.com/open-rails/authkit/iam"

// Route-surface generation (#111): the auto-generated management routes are
// DERIVED from each configured group persona. Public routes
// and permission strings call that configured name the persona: a `merchant` persona
// emits `/merchant/:instance_slug/...` routes gated by `merchant:<area>:<action>`.
// A disabled capability emits NO route, so calling it 404s, which is stronger
// than a runtime 403. Group ids never appear in a path.

// GeneratedRoute is one auto-generated management endpoint: addressed by the
// RESOURCE's own id (:instance_slug), gated by Perm (a concrete <persona>:<res>:<act>).
type GeneratedRoute struct {
	Persona iam.Persona
	Method  string
	Path    string // e.g. /merchant/:instance_slug/members
	Perm    iam.Perm
}

// GeneratedRoutes returns the full management surface implied by the schema's
// per-persona definition. The HTTP layer mounts exactly these; disabled
// capabilities are simply absent (→ 404). Reads gate on <area>:read;
// mutations on the matching <area>:manage built-in.
func GeneratedRoutes(s *iam.GroupSchema) []GeneratedRoute {
	var out []GeneratedRoute
	for _, persona := range s.Personas() {
		td, _ := s.Persona(persona)
		base := "/" + string(persona) + "/:instance_slug"
		caps := td.Capabilities
		memberRoutes := persona != iam.RootPersona

		if memberRoutes {
			rd, mg := iam.PermMembersRead(persona), iam.PermMembersManage(persona)
			out = append(out,
				GeneratedRoute{persona, "GET", base + "/members", rd},
				GeneratedRoute{persona, "POST", base + "/members", mg},
				GeneratedRoute{persona, "DELETE", base + "/members/:user", mg},
				GeneratedRoute{persona, "PUT", base + "/members/:user/roles/:role", mg},
				// #264: group settings — slug rename (tombstone-forwarding)
				// and display-name changes. Owner-controlled via the wildcard.
				GeneratedRoute{persona, "PATCH", base, iam.PermSettingsManage(persona)},
				// #269: the instance's own identity descriptor — the read
				// symmetric of the PATCH, and the only place a caller outside
				// the process learns the group's uuid. Creation reports it
				// once; this route is how it stays recoverable (and how an
				// instance created before #269 becomes addressable at all).
				GeneratedRoute{persona, "GET", base, iam.PermSettingsRead(persona)},
			)
		}
		// Listing the role catalog is part of visible role/member management;
		// personas with every management capability off emit no public routes.
		if memberRoutes || caps.CustomRoles {
			out = append(out, GeneratedRoute{persona, "GET", base + "/roles", iam.PermRolesRead(persona)})
		}
		if caps.CustomRoles {
			mg := iam.PermRolesManage(persona)
			out = append(out,
				GeneratedRoute{persona, "POST", base + "/roles", mg},
				GeneratedRoute{persona, "DELETE", base + "/roles/:role", mg},
			)
		}
		if caps.APIKeys {
			rd, mg := iam.PermCredentialsRead(persona), iam.PermCredentialsManage(persona)
			out = append(out,
				GeneratedRoute{persona, "GET", base + "/api-keys", rd},
				GeneratedRoute{persona, "POST", base + "/api-keys", mg},
				GeneratedRoute{persona, "DELETE", base + "/api-keys/:key", mg},
			)
		}
		if caps.RemoteApplications {
			rd, mg := iam.PermCredentialsRead(persona), iam.PermCredentialsManage(persona)
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
			rd, mg := iam.PermMembersRead(persona), iam.PermMembersManage(persona)
			out = append(out,
				GeneratedRoute{persona, "POST", base + "/invites/links", mg},
				GeneratedRoute{persona, "GET", base + "/invites/links", rd},
				GeneratedRoute{persona, "DELETE", base + "/invites/links/:link", mg},
			)
		}
	}
	return out
}
