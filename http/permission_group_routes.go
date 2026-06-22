package authhttp

// Auto-generated per-persona group-management HTTP surface (#111, task #15).
//
// The route surface IS the capability spec: core.GroupSchema.GeneratedRoutes()
// emits one GeneratedRoute per enabled management capability per type, addressed
// by the RESOURCE id (:resource-id) and gated by a concrete <persona>:<area>:<action>
// perm. A disabled capability emits NO route here, so calling it 404s — strictly
// stronger than a runtime 403.
//
// This file translates that data surface into RouteSpec handlers and mounts them
// via the same APIRoutes/route-table mechanism the rest of authhttp uses. Group
// ids stay internal: every handler resolves (persona, :resource-id) -> group by
// resource_ref inside the Service, then authorizes via svc.Can before acting.

import (
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

// RoutePermissionGroups is the route group for the auto-generated per-persona
// group-management surface plus the cross-persona /me/groups discovery route.
const RoutePermissionGroups RouteGroup = "permission_groups"

// groupCan is the authorization predicate the generated handlers gate on. It
// defaults to core.Service.Can; it is a field only so handler tests can stub the
// decision without a database (production never reassigns it).
func (s *Service) groupCan(r *http.Request, subjectID, persona, resourceID, perm string) (bool, error) {
	if s.groupCanFn != nil {
		return s.groupCanFn(r, subjectID, persona, resourceID, perm)
	}
	return s.svc.Can(r.Context(), subjectID, core.SubjectKindUser, persona, resourceID, perm)
}

// notImplemented is the wire code for a generated route whose operation is not
// wired yet (the api-keys / remote-applications / invites families are stubbed).
const notImplemented ErrorCode = "not_implemented"

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
	required := Required(s.verifier)
	lang := func(h http.Handler) http.Handler { return LanguageMiddleware(s.langCfg)(h) }

	specs := s.permissionGroupRouteSpecs()
	// Cross-persona discovery endpoint (not schema-derived; always present).
	specs = append(specs, RouteSpec{
		Method:  http.MethodGet,
		Path:    "/me/groups",
		Group:   RoutePermissionGroups,
		Handler: http.HandlerFunc(s.handleMeGroupsGET),
	})

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
	return generatedRouteSpecs(s, s.svc.PermissionGroupSchema().GeneratedRoutes())
}

// generatedRouteSpecs translates core GeneratedRoutes into authhttp RouteSpecs,
// binding a handler per route that gates on route.Perm and dispatches by the
// route's path SHAPE (members / members-role / roles / api-keys / ...). The
// generator's `:param` paths are converted to net/http ServeMux `{param}` syntax.
func generatedRouteSpecs(s *Service, routes []core.GeneratedRoute) []RouteSpec {
	out := make([]RouteSpec, 0, len(routes))
	for _, gr := range routes {
		gr := gr // capture per-iteration
		out = append(out, RouteSpec{
			Method:  gr.Method,
			Path:    muxPath(gr.Path),
			Group:   RoutePermissionGroups,
			Handler: s.generatedGroupHandler(gr),
		})
	}
	return out
}

// muxPath rewrites the generator's colon-style params (":resource-id", ":user",
// ":role", ...) into net/http ServeMux wildcards ("{resource-id}", "{user}", ...).
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
// "resource-id"), accounting for the hyphen->underscore wildcard rewrite.
func pathParam(r *http.Request, name string) string {
	return strings.TrimSpace(r.PathValue(strings.ReplaceAll(name, "-", "_")))
}

// generatedGroupHandler returns the handler for one generated route. It:
//  1. extracts the caller's verified claims (401 if absent);
//  2. resolves persona + :resource-id from the route/path;
//  3. authorizes via svc.Can(caller, "user", persona, resource-id, route.Perm)
//     (403 on deny);
//  4. performs the operation. members + members/:user/roles/:role are fully
//     wired; the api-keys / remote-applications / invites families return 501.
func (s *Service) generatedGroupHandler(gr core.GeneratedRoute) http.HandlerFunc {
	op := classifyGeneratedRoute(gr.Method, gr.Path)
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok || claims.UserID == "" {
			unauthorized(w, ErrNotAuthenticated)
			return
		}
		resourceID := pathParam(r, "resource-id")
		if resourceID == "" {
			badRequest(w, ErrInvalidRequest)
			return
		}

		// Authorize: the caller (a user) must hold route.Perm on this group.
		allowed, err := s.groupCan(r, claims.UserID, gr.Persona, resourceID, gr.Perm)
		if err != nil {
			serverErr(w, ErrDatabaseError)
			return
		}
		if !allowed {
			forbidden(w, ErrForbidden)
			return
		}

		switch op {
		case opMembersList:
			s.groupMembersList(w, r, gr.Persona, resourceID)
		case opMemberAdd:
			s.groupMemberAdd(w, r, gr.Persona, resourceID)
		case opMemberRemove:
			s.groupMemberRemove(w, r, gr.Persona, resourceID, pathParam(r, "user"))
		case opMemberRoleAssign:
			s.groupMemberRole(w, r, gr.Persona, resourceID, pathParam(r, "user"), pathParam(r, "role"), true)
		case opMemberRoleUnassign:
			s.groupMemberRole(w, r, gr.Persona, resourceID, pathParam(r, "user"), pathParam(r, "role"), false)
		case opRolesList:
			s.groupRolesList(w, gr.Persona)
		default:
			// roles-define / api-keys / remote-applications / invites: not wired yet.
			sendErr(w, http.StatusNotImplemented, notImplemented)
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
	opMemberRoleUnassign
	opRolesList
)

// classifyGeneratedRoute maps a generator route (its method + colon-param path)
// to a wired operation. The trailing path shape is stable across personas; the
// method disambiguates the collapse points (GET vs POST /members, PUT vs DELETE
// on /members/:user/roles/:role). Everything else (custom-role define, api-keys,
// remote-applications, invites) is opStub (=> 501).
func classifyGeneratedRoute(method, path string) generatedOp {
	switch {
	case strings.HasSuffix(path, "/members/:user/roles/:role"):
		if method == http.MethodPut {
			return opMemberRoleAssign
		}
		return opMemberRoleUnassign // DELETE
	case strings.HasSuffix(path, "/members/:user"):
		return opMemberRemove // DELETE
	case strings.HasSuffix(path, "/members"):
		if method == http.MethodPost {
			return opMemberAdd
		}
		return opMembersList // GET
	case strings.HasSuffix(path, "/roles"):
		if method == http.MethodGet {
			return opRolesList
		}
		return opStub // POST /roles (custom-role define) not wired
	default:
		return opStub
	}
}
