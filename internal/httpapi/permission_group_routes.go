package httpapi

// The group-management HTTP surface (group_routes.go) and the caller's own
// groups and permissions. Every group route resolves :group_id, refuses a
// group whose persona lacks the route, and authorizes the route's permission
// with the engine's live Can before the operation applies its own rules.

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// groupScopeCodes: a group-scoped route answers an unknown group as forbidden,
// not not_found, so it does not enumerate groups.
var groupScopeCodes = map[error]errmodel.Code{iam.ErrGroupNotFound: errmodel.CodeForbidden}

// PermissionGroupRoutes returns the group-management routes some persona has,
// plus the caller's own groups and permissions. Mirrors APIRoutes:
// prefix-neutral RouteSpecs, rate-limited by their bucket, language-wrapped and
// gated by their tier.
func (s *Service) PermissionGroupRoutes() []RouteSpec {
	if s == nil || s.svc == nil {
		return nil
	}
	lang := func(h http.Handler) http.Handler { return LanguageMiddleware(s.langCfg)(h) }

	specs := s.permissionGroupRouteSpecs()
	specs = append(specs, RouteSpec{
		Method:  http.MethodGet,
		Path:    "/me/groups",
		Group:   iam.RouteAccount,
		Auth:    iam.AuthRequired,
		Handler: http.HandlerFunc(s.handleMeGroupsGET),
	})
	// Permission introspection (#421): the caller's effective grants in one
	// group (?group_id=; defaults to the root group), so a client gates UI on
	// permission strings instead of expanding role names.
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
			Auth:    iam.AuthSession,
			Bucket:  RLInviteRedeem,
			Handler: http.HandlerFunc(s.handleInviteRedeemPOST),
		})
	}

	out := make([]RouteSpec, 0, len(specs))
	for _, spec := range specs {
		spec.Handler = lang(s.rateLimitedRoute(spec.Bucket, s.authenticate(spec.Auth, spec.Handler)))
		out = append(out, spec)
	}
	return out
}

// permissionGroupRouteSpecs builds the group-management RouteSpecs (without
// middleware) from the declared schema.
func (s *Service) permissionGroupRouteSpecs() []RouteSpec {
	routes := MountedGroupRoutes(s.svc.PermissionGroupSchema())
	out := make([]RouteSpec, 0, len(routes))
	for _, gr := range routes {
		out = append(out, RouteSpec{
			Method:     gr.Method,
			Path:       MuxPath(gr.Path),
			Group:      iam.RoutePermissionGroups,
			Auth:       iam.AuthPermission,
			Permission: gr.Op.catalogPermission(),
			Handler:    s.GroupHandler(gr),
		})
	}
	return out
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

// MuxPath rewrites colon-style params (":group_id", ":user", ...) into
// net/http ServeMux wildcards ("{group_id}", "{user}", ...).
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

// pathParam reads a ServeMux path value by its colon name (e.g. "group_id"),
// accounting for the hyphen->underscore wildcard rewrite.
func pathParam(r *http.Request, name string) string {
	return strings.TrimSpace(r.PathValue(strings.ReplaceAll(name, "-", "_")))
}

// GroupHandler returns the handler for one group route. It:
//  1. derives the caller's actor (401 if none; 403 for a delegation);
//  2. resolves :group_id to a live group;
//  3. refuses a group whose persona lacks the route, like an unknown group;
//  4. authorizes the route's permission on the group with the engine's live
//     Can, for every actor kind (403 on deny);
//  5. performs the operation, whose engine call applies its own rules.
func (s *Service) GroupHandler(gr GroupRoute) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := verify.ActorFromContext(r.Context())
		if !ok {
			fail(w, errmodel.CodeUnauthenticated)
			return
		}
		// AuthKit's management routes refuse delegated principals.
		if actor.Kind() == iam.ActorDelegated {
			fail(w, errmodel.CodeForbidden)
			return
		}
		g, err := s.svc.Group(r.Context(), iam.GroupByID(pathParam(r, "group_id")))
		if err == nil && g.DeletedAt != nil {
			err = iam.ErrGroupNotFound
		}
		if err != nil {
			writeError(w, remap(err, groupScopeCodes))
			return
		}
		persona, ok := s.svc.PermissionGroupSchema().Persona(g.Persona)
		if !ok || !gr.Op.Available(persona) {
			fail(w, errmodel.CodeForbidden)
			return
		}
		group := iam.GroupByID(g.ID)
		allowed := false
		for _, perm := range gr.Op.Perms(persona) {
			if allowed, err = s.svc.Can(r.Context(), actor, group, perm); err != nil || allowed {
				break
			}
		}
		if errors.Is(err, iam.ErrSessionRevoked) {
			writeError(w, err)
			return
		}
		if err != nil {
			serverErr(w, "database_error", err)
			return
		}
		if !allowed {
			fail(w, errmodel.CodeForbidden)
			return
		}

		switch gr.Op {
		case OpMembersList:
			s.groupMembersList(w, r, g)
		case OpMemberAdd:
			s.groupMemberAdd(w, r, g, actor)
		case OpMemberRemove:
			s.groupMemberRemove(w, r, g, actor, pathParam(r, "user"))
		case OpMemberRoleAssign:
			s.groupMemberRole(w, r, g, actor, pathParam(r, "user"), pathParam(r, "role"))
		case OpRolesList:
			s.groupRolesList(w, g)
		case OpAPIKeysList:
			s.groupAPIKeyList(w, r, g)
		case OpAPIKeyMint:
			s.groupAPIKeyMint(w, r, g, actor)
		case OpAPIKeyRevoke:
			s.groupAPIKeyRevoke(w, r, g, actor, pathParam(r, "key"))
		case OpInviteLinkList:
			s.groupInviteLinkList(w, r, g)
		case OpInviteLinkMint:
			s.groupInviteLinkMint(w, r, g, actor)
		case OpInviteLinkRevoke:
			s.groupInviteLinkRevoke(w, r, g, actor, pathParam(r, "link"))
		default:
			fail(w, errmodel.CodeNotImplemented)
		}
	}
}

// userActorID is the user behind actor, for operations only a user may
// perform; any other actor gets 403.
func userActorID(w http.ResponseWriter, actor iam.Actor) (string, bool) {
	if actor.Kind() != iam.ActorUser {
		fail(w, errmodel.CodeForbidden)
		return "", false
	}
	return actor.ID(), true
}

// writeOpResult answers a single-item batch operation: its item error or ok.
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
// — one forbidden and one invalid_request per family.
var groupOpCodes = map[error]errmodel.Code{
	iam.ErrExternalInvitesDisabled:  errmodel.CodeForbidden,
	iam.ErrInsufficientAuthority:    errmodel.CodeForbidden,
	iam.ErrRoleAssignmentEscalation: errmodel.CodeForbidden,
	iam.ErrInvalidRemoteApplication: errmodel.CodeInvalidRequest,
	iam.ErrReservedIssuer:           errmodel.CodeInvalidRequest,
	errmodel.ErrInvitationExpired:   errmodel.CodeInvalidRequest,
	errmodel.ErrInvitationRevoked:   errmodel.CodeInvalidRequest,
	iam.ErrRoleNotAssignable:        errmodel.CodeInvalidRequest,
	errmodel.ErrMissingName:         errmodel.CodeInvalidRequest,
	errmodel.ErrInvalidInvite:       errmodel.CodeInvalidRequest,
	errmodel.ErrInvalidExpiry:       errmodel.CodeInvalidRequest,
	iam.ErrUnknownGroupPersona:      errmodel.CodeInvalidRequest,
}

// groupRole resolves role text `<persona>:<name>` for a group of persona. The
// wire carries roles only in this qualified form.
func (s *Service) groupRole(persona iam.Persona, text string) (iam.Role, error) {
	role, err := s.svc.Role(text)
	if err != nil {
		return iam.Role{}, err
	}
	if role.Persona() != persona {
		return iam.Role{}, fmt.Errorf("%q is not a role of a %q group: %w", text, persona, iam.ErrRoleNotAssignable)
	}
	return role, nil
}
