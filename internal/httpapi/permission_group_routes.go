package httpapi

// Auto-generated per-persona group-management HTTP surface (#111, task #15).
//
// The route surface IS the capability spec: GeneratedRoutes
// emits one GeneratedRoute per enabled management capability per persona,
// addressed by the RESOURCE slug (:instance_slug) and gated by a concrete
// <persona>:<area>:<action> perm. A disabled capability emits NO route here, so
// calling it 404s — strictly stronger than a runtime 403.
//
// This file translates that data surface into RouteSpec handlers and mounts them
// via the same APIRoutes/route-table mechanism the rest of httpapi uses. Group
// ids stay internal: every handler resolves (persona, :instance_slug) -> group by
// instance_slug inside the Service, then authorizes via svc.Can before acting.

import (
	"errors"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/verify"
)

// groupScopeCodes: a group-scoped route answers an unknown group as forbidden,
// not not_found, so it does not enumerate groups.
var groupScopeCodes = map[error]iam.Code{iam.ErrGroupNotFound: iam.CodeForbidden}

func (s *Service) groupCan(r *http.Request, subjectID string, group iam.GroupRef, perm iam.Perm) (bool, error) {
	return s.svc.Can(r.Context(), iam.UserSubject(subjectID), group, perm)
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
	specs = append(specs, RouteSpec{
		Method:  http.MethodGet,
		Path:    "/me/groups",
		Group:   iam.RouteAccount,
		Auth:    iam.AuthRequired,
		Handler: http.HandlerFunc(s.handleMeGroupsGET),
	})
	// Permission-introspection (#421): the caller's effective grants in one group
	// instance (?persona=, ?instance=; defaults to the singleton root group), so a
	// client gates UI on permission strings instead of expanding role slugs.
	specs = append(specs, RouteSpec{
		Method:  http.MethodGet,
		Path:    "/me/permissions",
		Group:   iam.RouteAccount,
		Auth:    iam.AuthRequired,
		Handler: http.HandlerFunc(s.handleMePermissionsGET),
	})
	if s.hasInviteLinkSupport() {
		specs = append(specs, RouteSpec{
			Method:  http.MethodPost,
			Path:    "/invites/redeem",
			Group:   iam.RoutePermissionGroups,
			Auth:    iam.AuthRequired,
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
	specs := generatedRouteSpecs(s, GeneratedRoutes(schema))
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
			Group:   iam.RoutePermissionGroups,
			Auth:    iam.AuthRequired,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.groupInstanceCreate(w, r, persona) }),
		})
	}
	return specs
}

func (s *Service) hasInviteLinkSupport() bool {
	if s == nil || s.svc == nil {
		return false
	}
	schema := s.svc.PermissionGroupSchema()
	for _, persona := range schema.Personas() {
		if persona != iam.RootPersona {
			return true
		}
	}
	return false
}

// generatedRouteSpecs translates core GeneratedRoutes into httpapi RouteSpecs,
// binding a handler per route that gates on route.Perm and dispatches by the
// route's path SHAPE (members / members-role / roles / api-keys / ...). The
// generator's `:param` paths are converted to net/http ServeMux `{param}` syntax.
func generatedRouteSpecs(s *Service, routes []GeneratedRoute) []RouteSpec {
	out := make([]RouteSpec, 0, len(routes))
	for _, gr := range routes {
		gr := gr // capture per-iteration
		out = append(out, RouteSpec{
			Method:     gr.Method,
			Path:       MuxPath(gr.Path),
			Group:      iam.RoutePermissionGroups,
			Auth:       iam.AuthPermission,
			Permission: gr.Perm,
			Handler:    s.GeneratedGroupHandler(gr),
		})
	}
	return out
}

// muxPath rewrites the generator's colon-style params (":instance_slug", ":user",
// ":role", ...) into net/http ServeMux wildcards ("{instance_slug}", "{user}", ...).
// ServeMux wildcard names may not contain '-', so hyphens become underscores;
// pathParam() reverses this when reading r.PathValue.
func MuxPath(p string) string {
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
//  1. derives the caller's actor once (401 if none);
//  2. resolves persona + :instance_slug from the route/path;
//  3. authorizes route.Perm (or route.OrPerm when set) on the group (403 on deny);
//  4. performs the operation, passing the actor to the operation handler,
//     where the engine applies the operation's own authority rules.
func (s *Service) GeneratedGroupHandler(gr GeneratedRoute) http.HandlerFunc {
	op := classifyGeneratedRoute(gr.Method, gr.Path)
	// Remote-application self credentials may use the member operations only.
	remoteOperation := op == opMemberAdd || op == opMemberRemove || op == opMemberRoleAssign || op == opMembersList || op == opRolesList
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := verify.ActorFromContext(r.Context())
		if !ok || !(actor.Kind() == iam.ActorUser || actor.Kind() == iam.ActorRemoteApplication && remoteOperation) {
			unauthorized(w, iam.CodeNotAuthenticated)
			return
		}
		instanceSlug := pathParam(r, "instance_slug")
		if instanceSlug == "" {
			badRequest(w, iam.CodeInvalidRequest)
			return
		}

		group := iam.GroupBySlug(gr.Persona, instanceSlug)
		instance, err := s.svc.GroupInstanceForSlug(r.Context(), group)
		if err != nil {
			writeError(w, remap(err, groupScopeCodes))
			return
		}
		r = r.WithContext(authflow.WithResolvedGroup(r.Context(), instance, instanceSlug))

		// Native authority is live. Remote self credentials additionally remain
		// bound to their controlling group and verified permission ceiling.
		check := func(perm iam.Perm) (bool, error) {
			if actor.Kind() != iam.ActorRemoteApplication {
				return s.groupCan(r, actor.ID(), group, perm)
			}
			claims, _ := verify.ClaimsFromContext(r.Context())
			if !claims.PermissionGroupAllows(verify.PermissionScope{GroupID: instance.ID, AuthorityIssuer: s.settings.Issuer, Persona: gr.Persona}) || !actor.CeilingCovers(perm) {
				return false, nil
			}
			return s.svc.Can(r.Context(), iam.RemoteApplicationSubject(actor.ID()), group, perm)
		}
		allowed, err := check(gr.Perm)
		if err == nil && !allowed && gr.OrPerm != "" {
			allowed, err = check(gr.OrPerm)
		}
		if err != nil {
			serverErr(w, iam.CodeDatabaseError, err)
			return
		}
		if !allowed {
			forbidden(w, iam.CodeForbidden)
			return
		}

		w.Header().Set("X-AuthKit-Group-ID", instance.ID)
		w.Header().Set("X-AuthKit-Canonical-Instance", instance.InstanceSlug)
		switch op {
		case opMembersList:
			s.groupMembersList(w, r, group, actor)
		case opMemberAdd:
			s.groupMemberAdd(w, r, group, actor)
		case opMemberRemove:
			s.groupMemberRemove(w, r, group, actor, pathParam(r, "user"))
		case opMemberRoleAssign:
			s.groupMemberRole(w, r, group, actor, pathParam(r, "user"), iam.Role(pathParam(r, "role")))
		case opRolesList:
			s.groupRolesList(w, gr.Persona)
		case opRoleDefine:
			s.groupCustomRoleDefine(w, r, group, actor)
		case opRoleDelete:
			s.groupCustomRoleDelete(w, r, group, actor, iam.Role(pathParam(r, "role")))
		case opAPIKeysList:
			s.groupAPIKeyList(w, r, group, actor)
		case opAPIKeyMint:
			s.groupAPIKeyMint(w, r, group, actor)
		case opAPIKeyRevoke:
			s.groupAPIKeyRevoke(w, r, group, actor, pathParam(r, "key"))
		case opRemoteAppsList:
			s.groupRemoteAppList(w, r, group, actor)
		case opRemoteAppRegister:
			s.groupRemoteAppRegister(w, r, group, actor)
		case opRemoteAppDelete:
			s.groupRemoteAppDelete(w, r, group, actor, pathParam(r, "app"))
		case opRemoteAppRoleAssign:
			s.groupRemoteAppRole(w, r, group, actor, pathParam(r, "app"), iam.Role(pathParam(r, "role")))
		case opInviteLinkList:
			s.groupInviteLinkList(w, r, group, actor)
		case opInviteLinkMint:
			s.groupInviteLinkMint(w, r, group, actor)
		case opInviteLinkRevoke:
			s.groupInviteLinkRevoke(w, r, group, actor, pathParam(r, "link"))
		case opGroupUpdate:
			s.groupUpdate(w, r, group, actor)
		case opGroupRead:
			s.groupInstanceDescriptor(w, r, group, actor)
		default:
			// roles-define (POST/DELETE /roles): not wired yet.
			sendErr(w, http.StatusNotImplemented, iam.CodeNotImplemented)
		}
	}
}

// userActorID is the user behind actor, for operations only a user may
// perform; any other actor gets 403.
func userActorID(w http.ResponseWriter, actor iam.Actor) (string, bool) {
	if actor.Kind() != iam.ActorUser {
		forbidden(w, iam.CodeForbidden)
		return "", false
	}
	return actor.ID(), true
}

// writeOpResult answers a single-item batch operation: its item error or ok.
func (s *Service) writeOpResult(w http.ResponseWriter, results []iam.OpResult, err error) bool {
	if err == nil && len(results) == 1 {
		err = results[0].Err
	}
	if err != nil {
		s.writeGroupOpError(w, err)
		return false
	}
	return true
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

// writeGroupOpError answers a group-operation failure: the 2FA-enrollment
// refusal carries the enrollment metadata, everything else is the catalog's
// status and code through notFoundCodes/groupOpCodes.
func (s *Service) writeGroupOpError(w http.ResponseWriter, err error) {
	if errors.Is(err, iam.ErrTwoFAEnrollmentRequired) {
		s.send2FAEnrollmentRequiredError(w)
		return
	}
	writeError(w, remap(err, notFoundCodes, groupOpCodes))
}

// groupOpCodes: where a group operation's wire code differs from the catalog
// — one forbidden and one invalid_request per family, and the last-owner
// refusal (#193: unsafe, not unauthorised, so 409).
var groupOpCodes = map[error]iam.Code{
	iam.ErrCannotRemoveLastAdminRole:     iam.CodeCannotRemoveLastOwner,
	iam.ErrExternalInvitesDisabled:       iam.CodeForbidden,
	iam.ErrInsufficientRoleAuthority:     iam.CodeForbidden,
	iam.ErrRoleAssignmentEscalation:      iam.CodeForbidden,
	iam.ErrInvalidRemoteApplication:      iam.CodeInvalidRequest,
	iam.ErrReservedIssuer:                iam.CodeInvalidRequest,
	iam.ErrInviteLinkExpired:             iam.CodeInvalidRequest,
	iam.ErrInviteLinkRevoked:             iam.CodeInvalidRequest,
	iam.ErrRoleNotAssignable:             iam.CodeInvalidRequest,
	iam.ErrInvalidRole:                   iam.CodeInvalidRequest,
	iam.ErrUnknownRole:                   iam.CodeInvalidRequest,
	iam.ErrMissingName:                   iam.CodeInvalidRequest,
	iam.ErrInvalidInvite:                 iam.CodeInvalidRequest,
	iam.ErrInvalidExpiry:                 iam.CodeInvalidRequest,
	iam.ErrUnknownGroupPersona:           iam.CodeInvalidRequest,
	iam.ErrCustomRolesNotSupported:       iam.CodeInvalidRequest,
	iam.ErrCustomRoleNameInvalid:         iam.CodeInvalidRequest,
	iam.ErrCustomRoleIsCatalogRole:       iam.CodeInvalidRequest,
	iam.ErrCustomRoleGrantCrossPersona:   iam.CodeInvalidRequest,
	iam.ErrCustomRoleGrantOutsideCatalog: iam.CodeInvalidRequest,
}
