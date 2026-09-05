package authhttp

// Auto-generated per-persona group-management HTTP surface (#111, task #15).
//
// The route surface IS the capability spec: embedded.GroupSchema.GeneratedRoutes()
// emits one GeneratedRoute per enabled management capability per persona,
// addressed by the RESOURCE slug (:instance_slug) and gated by a concrete
// <persona>:<area>:<action> perm. A disabled capability emits NO route here, so
// calling it 404s — strictly stronger than a runtime 403.
//
// This file translates that data surface into RouteSpec handlers and mounts them
// via the same APIRoutes/route-table mechanism the rest of authhttp uses. Group
// ids stay internal: every handler resolves (persona, :instance_slug) -> group by
// instance_slug inside the Service, then authorizes via svc.Can before acting.

import (
	"net/http"
	"strings"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/verify"

	"github.com/open-rails/authkit/embedded"
)

// groupScopeCodes: a group-scoped route answers an unknown group as forbidden,
// not not_found, so it does not enumerate groups.
var groupScopeCodes = map[error]authkit.Code{authkit.ErrGroupNotFound: authkit.CodeForbidden}

func (s *Service) groupCan(r *http.Request, subjectID string, group authkit.GroupRef, perm authkit.Perm) (bool, error) {
	return s.svc.Can(r.Context(), authkit.UserSubject(subjectID), group, perm)
}

// PermissionGroupRoutes returns the auto-generated management routes implied by
// this Service's declared permission-group schema, plus the cross-persona
// GET /me/groups discovery route. Mirrors APIRoutes: prefix-neutral RouteSpecs in
// the RoutePermissionGroups group, language-wrapped and auth-required. The set is
// fully config-derived from svc.PermissionGroupSchema().GeneratedRoutes(); a
// capability a profile disables is simply absent (=> 404).
func (s *Service) PermissionGroupRoutes() []RouteSpec {
	if s == nil || s.svc == nil || s.verifier == nil {
		return nil
	}
	required := verify.Required(s.verifier)
	lang := func(h http.Handler) http.Handler { return LanguageMiddleware(s.langCfg)(h) }

	specs := s.permissionGroupRouteSpecs()
	if s.hasUserVisibleMemberships() {
		specs = append(specs, RouteSpec{
			Method:  http.MethodGet,
			Path:    "/me/groups",
			Group:   RouteAccount,
			Auth:    AuthRequired,
			Handler: http.HandlerFunc(s.handleMeGroupsGET),
		})
	}
	// Permission-introspection (#421): the caller's effective grants in one group
	// instance (?persona=, ?instance=; defaults to the singleton root group), so a
	// client gates UI on permission strings instead of expanding role slugs.
	specs = append(specs, RouteSpec{
		Method:  http.MethodGet,
		Path:    "/me/permissions",
		Group:   RouteAccount,
		Auth:    AuthRequired,
		Handler: http.HandlerFunc(s.handleMePermissionsGET),
	})
	if s.hasInviteLinkSupport() {
		specs = append(specs, RouteSpec{
			Method:  http.MethodPost,
			Path:    "/invites/redeem",
			Group:   RoutePermissionGroups,
			Auth:    AuthRequired,
			Handler: http.HandlerFunc(s.handleInviteRedeemPOST),
		})
	}

	out := make([]RouteSpec, 0, len(specs))
	for _, spec := range specs {
		spec.Handler = lang(required(spec.Handler))
		out = append(out, spec)
	}
	return out
}

// permissionGroupRouteSpecs builds the management RouteSpecs (without middleware)
// from the declared schema. Split out from PermissionGroupRoutes so the route
// TABLE is unit-testable against a schema profile with no middleware/DB.
func (s *Service) permissionGroupRouteSpecs() []RouteSpec {
	schema := s.svc.PermissionGroupSchema()
	specs := generatedRouteSpecs(s, schema.GeneratedRoutes())
	// #263: the generated CREATION route — POST /<persona> — for personas that
	// opt in. Not instance-addressed (no instance exists yet), so it is gated
	// by authentication + velocity limits + the reserved-slug/admission policy
	// in the core create path rather than an instance permission.
	for _, persona := range schema.Personas() {
		if !schema.CreationEnabled(persona) {
			continue
		}
		persona := persona
		specs = append(specs, RouteSpec{
			Method:  http.MethodPost,
			Path:    "/" + string(persona),
			Group:   RoutePermissionGroups,
			Auth:    AuthRequired,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.groupInstanceCreate(w, r, persona) }),
		})
	}
	return specs
}

func (s *Service) hasUserVisibleMemberships() bool {
	if s == nil || s.svc == nil {
		return false
	}
	schema := s.svc.PermissionGroupSchema()
	for _, persona := range schema.Personas() {
		if persona != authkit.RootPersona {
			return true
		}
	}
	return false
}

func (s *Service) hasInviteLinkSupport() bool {
	if s == nil || s.svc == nil {
		return false
	}
	schema := s.svc.PermissionGroupSchema()
	for _, persona := range schema.Personas() {
		if persona != authkit.RootPersona {
			return true
		}
	}
	return false
}

// generatedRouteSpecs translates core GeneratedRoutes into authhttp RouteSpecs,
// binding a handler per route that gates on route.Perm and dispatches by the
// route's path SHAPE (members / members-role / roles / api-keys / ...). The
// generator's `:param` paths are converted to net/http ServeMux `{param}` syntax.
func generatedRouteSpecs(s *Service, routes []embedded.GeneratedRoute) []RouteSpec {
	out := make([]RouteSpec, 0, len(routes))
	for _, gr := range routes {
		gr := gr // capture per-iteration
		out = append(out, RouteSpec{
			Method:     gr.Method,
			Path:       muxPath(gr.Path),
			Group:      RoutePermissionGroups,
			Auth:       AuthPermission,
			Permission: gr.Perm,
			Handler:    s.generatedGroupHandler(gr),
		})
	}
	return out
}

// muxPath rewrites the generator's colon-style params (":instance_slug", ":user",
// ":role", ...) into net/http ServeMux wildcards ("{instance_slug}", "{user}", ...).
// ServeMux wildcard names may not contain '-', so hyphens become underscores;
// pathParam() reverses this when reading r.PathValue.
func muxPath(p string) string {
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		if strings.HasPrefix(seg, ":") {
			segs[i] = "{" + strings.ReplaceAll(seg[1:], "-", "_") + "}"
		}
	}
	return strings.Join(segs, "/")
}

// pathParam reads a ServeMux path value by the generator's colon name (e.g.
// "instance_slug"), accounting for the hyphen->underscore wildcard rewrite.
func pathParam(r *http.Request, name string) string {
	return strings.TrimSpace(r.PathValue(strings.ReplaceAll(name, "-", "_")))
}

// generatedGroupHandler returns the handler for one generated route. It:
//  1. extracts the caller's verified claims (401 if absent);
//  2. resolves persona + :instance_slug from the route/path;
//  3. authorizes via svc.Can(caller, group, route.Perm)
//     (403 on deny);
//  4. performs the operation. members, roles (catalog read), api-keys,
//     remote-applications, and invites are fully wired; only custom-role
//     define/delete routes depend on custom-role support being enabled.
func (s *Service) generatedGroupHandler(gr embedded.GeneratedRoute) http.HandlerFunc {
	op := classifyGeneratedRoute(gr.Method, gr.Path)
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := verify.ClaimsFromContext(r.Context())
		if !ok || claims.UserID == "" {
			unauthorized(w, authkit.CodeNotAuthenticated)
			return
		}
		instanceSlug := pathParam(r, "instance_slug")
		if instanceSlug == "" {
			badRequest(w, authkit.CodeInvalidRequest)
			return
		}

		group := authkit.GroupRef{Persona: gr.Persona, Instance: instanceSlug}
		instance, err := s.svc.GroupInstanceForSlug(r.Context(), group)
		if err != nil {
			writeError(w, remap(err, groupScopeCodes))
			return
		}
		r = r.WithContext(embedded.WithResolvedGroup(r.Context(), instance, instanceSlug))

		// Authorize: the caller (a user) must hold route.Perm on this group.
		allowed, err := s.groupCan(r, claims.UserID, group, gr.Perm)
		if err != nil {
			serverErr(w, authkit.CodeDatabaseError)
			return
		}
		if !allowed {
			forbidden(w, authkit.CodeForbidden)
			return
		}

		w.Header().Set("X-AuthKit-Group-ID", instance.ID)
		w.Header().Set("X-AuthKit-Canonical-Instance", instance.InstanceSlug)
		switch op {
		case opMembersList:
			s.groupMembersList(w, r, group)
		case opMemberAdd:
			s.groupMemberAdd(w, r, group)
		case opMemberRemove:
			s.groupMemberRemove(w, r, group, pathParam(r, "user"))
		case opMemberRoleAssign:
			s.groupMemberRole(w, r, group, pathParam(r, "user"), authkit.Role(pathParam(r, "role")))
		case opRolesList:
			s.groupRolesList(w, gr.Persona)
		case opRoleDefine:
			s.groupCustomRoleDefine(w, r, group)
		case opRoleDelete:
			s.groupCustomRoleDelete(w, r, group, authkit.Role(pathParam(r, "role")))
		case opAPIKeysList:
			s.groupAPIKeyList(w, r, group)
		case opAPIKeyMint:
			s.groupAPIKeyMint(w, r, group, claims.UserID)
		case opAPIKeyRevoke:
			s.groupAPIKeyRevoke(w, r, group, pathParam(r, "key"))
		case opRemoteAppsList:
			s.groupRemoteAppList(w, r, group)
		case opRemoteAppRegister:
			s.groupRemoteAppRegister(w, r, group)
		case opRemoteAppDelete:
			s.groupRemoteAppDelete(w, r, group, pathParam(r, "app"))
		case opRemoteAppRoleAssign:
			s.groupRemoteAppRole(w, r, group, pathParam(r, "app"), authkit.Role(pathParam(r, "role")))
		case opInviteLinkList:
			s.groupInviteLinkList(w, r, group)
		case opInviteLinkMint:
			s.groupInviteLinkMint(w, r, group, claims.UserID)
		case opInviteLinkRevoke:
			s.groupInviteLinkRevoke(w, r, group, pathParam(r, "link"))
		case opGroupUpdate:
			s.groupUpdate(w, r, group)
		case opGroupRead:
			s.groupInstanceDescriptor(w, r, group)
		default:
			// roles-define (POST/DELETE /roles): not wired yet.
			sendErr(w, http.StatusNotImplemented, authkit.CodeNotImplemented)
		}
	}
}

// generatedOp identifies the operation a generated route (method + path shape)
// implies.
type generatedOp int

const (
	opStub generatedOp = iota // not wired (501)
	opMembersList
	opMemberAdd
	opMemberRemove
	opMemberRoleAssign
	opRolesList
	opRoleDefine
	opRoleDelete
	opAPIKeysList
	opAPIKeyMint
	opAPIKeyRevoke
	opRemoteAppsList
	opRemoteAppRegister
	opRemoteAppDelete
	opRemoteAppRoleAssign
	opInviteLinkList
	opInviteLinkMint
	opInviteLinkRevoke
	opGroupUpdate
	opGroupRead
)

// classifyGeneratedRoute maps a generator route (its method + colon-param path)
// to a wired operation. The trailing path shape is stable across personas; the
// method disambiguates GET vs POST /members. Unknown shapes are opStub (=> 501).
func classifyGeneratedRoute(method, path string) generatedOp {
	switch {
	case strings.HasSuffix(path, "/:instance_slug"):
		switch method {
		case http.MethodPatch:
			return opGroupUpdate // #264 group settings: slug rename + display name
		case http.MethodGet:
			return opGroupRead // #269 instance descriptor: id + slug + display name
		}
		return opStub
	case strings.HasSuffix(path, "/members/:user/roles/:role"):
		if method == http.MethodPut {
			return opMemberRoleAssign
		}
		return opStub
	// #263: must precede the generic "/roles/:role" (custom-role delete) case,
	// which would otherwise swallow this longer suffix.
	case strings.HasSuffix(path, "/remote-applications/:app/roles/:role"):
		if method == http.MethodPut {
			return opRemoteAppRoleAssign
		}
		return opStub
	case strings.HasSuffix(path, "/members/:user"):
		return opMemberRemove // DELETE
	case strings.HasSuffix(path, "/members"):
		if method == http.MethodPost {
			return opMemberAdd
		}
		return opMembersList // GET
	case strings.HasSuffix(path, "/roles/:role"):
		return opRoleDelete // DELETE custom role
	case strings.HasSuffix(path, "/roles"):
		if method == http.MethodGet {
			return opRolesList
		}
		return opRoleDefine // POST custom-role define
	case strings.HasSuffix(path, "/api-keys/:key"):
		return opAPIKeyRevoke // DELETE
	case strings.HasSuffix(path, "/api-keys"):
		if method == http.MethodPost {
			return opAPIKeyMint
		}
		return opAPIKeysList // GET
	case strings.HasSuffix(path, "/remote-applications/:app"):
		return opRemoteAppDelete // DELETE
	case strings.HasSuffix(path, "/remote-applications"):
		if method == http.MethodPost {
			return opRemoteAppRegister
		}
		return opRemoteAppsList // GET
	case strings.HasSuffix(path, "/invites/links/:link"):
		return opInviteLinkRevoke // DELETE
	case strings.HasSuffix(path, "/invites/links"):
		if method == http.MethodPost {
			return opInviteLinkMint
		}
		return opInviteLinkList // GET
	default:
		return opStub
	}
}
