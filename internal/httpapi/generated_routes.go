package httpapi

import (
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/rbac"
)

// Route-surface generation (#111): the auto-generated management routes are
// DERIVED from each configured group persona. Public routes
// and permission strings call that configured name the persona: a `merchant` persona
// emits `/merchant/:instance_slug/...` routes gated by `merchant:<area>:<action>`.
// A disabled capability emits NO route, so calling it 404s, which is stronger
// than a runtime 403. Group ids never appear in a path.

// GeneratedRoute is one auto-generated management endpoint: addressed by the
// RESOURCE's own id (:instance_slug), gated by Perm (a concrete
// <persona>:<res>:<act>). OrPerm, when set, also admits the caller.
type GeneratedRoute struct {
	Persona iam.Persona
	Method  string
	Path    string // e.g. /merchant/:instance_slug/members
	Perm    iam.Perm
	OrPerm  iam.Perm
}

// GeneratedRoutes returns the full management surface implied by the schema's
// per-persona definition. The HTTP layer mounts exactly these; disabled
// capabilities are simply absent (→ 404).
func GeneratedRoutes(s *rbac.Schema) []GeneratedRoute {
	var out []GeneratedRoute
	for _, persona := range s.Personas() {
		td, _ := s.Persona(persona)
		base := "/" + string(persona) + "/:instance_slug"
		add := func(method, path string, perm iam.Perm) {
			out = append(out, GeneratedRoute{Persona: persona, Method: method, Path: base + path, Perm: perm})
		}
		memberRoutes := persona != iam.RootPersona

		if memberRoutes {
			rd, mg := iam.PermMembersRead(persona), iam.PermMembersManage(persona)
			add("GET", "/members", rd)
			add("POST", "/members", mg)
			add("DELETE", "/members/:user", mg)
			add("PUT", "/members/:user/roles/:role", mg)
			// #264: the group itself — slug rename (tombstone-forwarding)
			// and display-name changes. Owner-controlled via the wildcard.
			add("PATCH", "", iam.PermSelfUpdate(persona))
			// #269: the instance's own identity descriptor, and the only
			// place a caller outside the process learns the group's uuid.
			add("GET", "", iam.PermSelfRead(persona))
		}
		// The role catalog is visible to member readers and custom-role managers.
		if memberRoutes || td.CustomRoles {
			roles := GeneratedRoute{Persona: persona, Method: "GET", Path: base + "/roles", Perm: iam.PermMembersRead(persona)}
			if td.CustomRoles {
				roles.OrPerm = iam.PermRolesManage(persona)
			}
			out = append(out, roles)
		}
		if td.CustomRoles {
			mg := iam.PermRolesManage(persona)
			add("POST", "/roles", mg)
			add("DELETE", "/roles/:role", mg)
		}
		if td.APIKeys {
			rd, mg := iam.PermCredentialsRead(persona), iam.PermCredentialsManage(persona)
			add("GET", "/api-keys", rd)
			add("POST", "/api-keys", mg)
			add("DELETE", "/api-keys/:key", mg)
		}
		if td.RemoteApplications {
			rd, mg := iam.PermCredentialsRead(persona), iam.PermCredentialsManage(persona)
			add("GET", "/remote-applications", rd)
			add("POST", "/remote-applications", mg)
			add("DELETE", "/remote-applications/:app", mg)
			// #263: the SubjectKindRemoteApp symmetric of the member-role route.
			add("PUT", "/remote-applications/:app/roles/:role", mg)
		}
		// Invite-LINK routes (#134). Redemption is the persona-agnostic POST
		// /invites/redeem, mounted as a fixed route.
		if memberRoutes {
			rd, mg := iam.PermMembersRead(persona), iam.PermMembersManage(persona)
			add("POST", "/invites/links", mg)
			add("GET", "/invites/links", rd)
			add("DELETE", "/invites/links/:link", mg)
		}
	}
	return out
}
