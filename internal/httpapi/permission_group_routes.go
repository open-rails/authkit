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
	"github.com/open-rails/helpers/auth"
)

// groupScopeCodes: a group-scoped route answers an unknown group as forbidden,
// not not_found, so it does not enumerate groups.
var groupScopeCodes = map[error]errmodel.Code{iam.ErrGroupNotFound: errmodel.CodeForbidden}

// GroupHandler returns the handler for one group route. It:
//  1. derives the caller's identity (401 if none; 403 for a delegation);
//  2. resolves :group_id (`root` is the root group) to a live group;
//  3. refuses a group whose persona lacks the route, like an unknown group;
//  4. authorizes the route's permission on the group with the engine's live
//     Can, for every identity kind (403 on deny);
//  5. for a change to the root group, requires a user who signed in
//     recently (M7): step_up_required otherwise, 403 for any other identity;
//  6. performs the operation, whose engine call applies its own rules.
func (s *Service) GroupHandler(op GroupOp) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		who, ok := verify.IdentityFromContext(r.Context())
		if !ok {
			fail(w, errmodel.CodeUnauthenticated)
			return
		}
		// AuthKit's management routes refuse delegations.
		if state(who).Delegated() {
			fail(w, errmodel.CodeForbidden)
			return
		}
		g, err := s.svc.Group(r.Context(), groupRef(r.PathValue("group_id")))
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
			if allowed, err = s.svc.Can(r.Context(), who, group, perm); err != nil || allowed {
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
		if op.Mutates() && g.Persona == iam.RootPersona() && !s.recentUserSignIn(w, r, who) {
			return
		}

		switch op {
		case OpMembersList:
			s.groupMembersList(w, r, g)
		case OpMemberSet:
			s.groupMemberSet(w, r, g, who)
		case OpMemberRemove:
			s.groupMemberRemove(w, r, g, who)
		case OpRolesList:
			s.groupRolesList(w, g)
		case OpAPIKeysList:
			s.groupAPIKeyList(w, r, g)
		case OpAPIKeyMint:
			s.groupAPIKeyMint(w, r, g, who)
		case OpAPIKeyRevoke:
			s.groupAPIKeyRevoke(w, r, g, who, r.PathValue("id"))
		case OpInvitationsList:
			s.groupInvitationsList(w, r, g)
		case OpInvitationCreate:
			s.groupInvitationCreate(w, r, g, who)
		case OpInvitationRevoke:
			s.groupInvitationRevoke(w, r, g, who, r.PathValue("id"))
		default:
			fail(w, errmodel.CodeNotImplemented)
		}
	}
}

// rootGroupID is the {group_id} that addresses the root group.
const rootGroupID = "root"

// groupRef resolves a {group_id} path value.
func groupRef(id string) iam.GroupRef {
	if id == rootGroupID {
		return iam.RootGroup()
	}
	return iam.GroupByID(id)
}

// recentUserSignIn admits a change to the root group only from a user who
// signed in recently (CheckRecentSignIn, MFA-fresh when enrolled): API keys
// and applications never change root, and a stale session is asked to step
// up. It answers the refusal itself.
func (s *Service) recentUserSignIn(w http.ResponseWriter, r *http.Request, who auth.Identity) bool {
	if !state(who).IsUser() {
		fail(w, errmodel.CodeForbidden)
		return false
	}
	claims, err := callerClaims(r)
	if err == nil {
		err = s.svc.CheckRecentSignIn(r.Context(), claims)
	}
	if err != nil {
		writeError(w, err)
		return false
	}
	return true
}

// userSubjectID is the user behind identity, for operations only a user may
// perform; any other identity gets 403.
func userSubjectID(w http.ResponseWriter, who auth.Identity) (string, bool) {
	if !state(who).IsUser() {
		fail(w, errmodel.CodeForbidden)
		return "", false
	}
	return state(who).ID(), true
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
