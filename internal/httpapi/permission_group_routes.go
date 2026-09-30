package httpapi

// The group-management HTTP surface (group_routes.go) and the caller's own
// groups and permissions. Every group route resolves :group_id, refuses a
// group whose persona lacks the route, and authorizes the route's permission
// with the engine's live Can before the operation applies its own rules.

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// groupScopeCodes: a group-scoped route answers an unknown group as forbidden,
// not not_found, so it does not enumerate groups.
var groupScopeCodes = map[error]errmodel.Code{iam.ErrGroupNotFound: errmodel.CodeForbidden}

// GroupHandler returns the handler for one group route. It:
//  1. derives the caller's actor (401 if none; 403 for a delegation);
//  2. resolves :group_id to a live group;
//  3. refuses a group whose persona lacks the route, like an unknown group;
//  4. authorizes the route's permission on the group with the engine's live
//     Can, for every actor kind (403 on deny);
//  5. performs the operation, whose engine call applies its own rules.
func (s *Service) GroupHandler(op GroupOp) http.HandlerFunc {
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
		g, err := s.svc.Group(r.Context(), iam.GroupByID(r.PathValue("group_id")))
		if err == nil && g.DeletedAt != nil {
			err = iam.ErrGroupNotFound
		}
		if err != nil {
			writeError(w, remap(err, groupScopeCodes))
			return
		}
		persona, ok := s.svc.PermissionGroupSchema().Persona(g.Persona)
		if !ok || !op.Available(persona) {
			fail(w, errmodel.CodeForbidden)
			return
		}
		group := iam.GroupByID(g.ID)
		allowed := false
		for _, perm := range op.Perms(persona) {
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

		switch op {
		case OpMembersList:
			s.groupMembersList(w, r, g)
		case OpMemberAdd:
			s.groupMemberAdd(w, r, g, actor)
		case OpMemberRemove:
			s.groupMemberRemove(w, r, g, actor, r.PathValue("user"))
		case OpMemberRoleAssign:
			s.groupMemberRole(w, r, g, actor, r.PathValue("user"), r.PathValue("role"))
		case OpRolesList:
			s.groupRolesList(w, g)
		case OpAPIKeysList:
			s.groupAPIKeyList(w, r, g)
		case OpAPIKeyMint:
			s.groupAPIKeyMint(w, r, g, actor)
		case OpAPIKeyRevoke:
			s.groupAPIKeyRevoke(w, r, g, actor, r.PathValue("key"))
		case OpInviteLinkList:
			s.groupInviteLinkList(w, r, g)
		case OpInviteLinkMint:
			s.groupInviteLinkMint(w, r, g, actor)
		case OpInviteLinkRevoke:
			s.groupInviteLinkRevoke(w, r, g, actor, r.PathValue("link"))
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
