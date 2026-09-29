package httpapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// Root-role administration is for signed-in users only: API keys, applications
// and delegated tokens never reach the management plane. The engine enforces
// root:members:manage, coverage of the role (so a bounded admin can promote to
// roles it holds, never to owner), the last owner and MFA-required roles.

// handleAdminRolesGET lists the root role catalog.
func (s *Service) handleAdminRolesGET(w http.ResponseWriter, r *http.Request) {
	g, err := s.svc.Group(r.Context(), iam.RootGroup())
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	s.groupRolesList(w, g)
}

func (s *Service) handleAdminUserRolePUT(w http.ResponseWriter, r *http.Request) {
	s.adminUserRole(w, r, s.svc.AssignGroupRoles)
}

func (s *Service) handleAdminUserRoleDELETE(w http.ResponseWriter, r *http.Request) {
	s.adminUserRole(w, r, s.svc.UnassignGroupRoles)
}

type rootRoleOp func(ctx context.Context, a iam.Actor, ref iam.GroupRef, subjects []iam.Subject, role iam.Role) ([]iam.OpResult, error)

func (s *Service) adminUserRole(w http.ResponseWriter, r *http.Request, op rootRoleOp) {
	actor, ok := verify.ActorFromContext(r.Context())
	if !ok {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	if _, ok := userActorID(w, actor); !ok {
		return
	}
	userID := strings.TrimSpace(r.PathValue("user_id"))
	name := strings.TrimSpace(r.PathValue("role"))
	if userID == "" || name == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	role, err := s.svc.PermissionGroupSchema().ParseRole(iam.RootPersona, name)
	if err != nil {
		writeError(w, remap(err, notFoundCodes, groupOpCodes))
		return
	}
	res, err := op(r.Context(), actor, iam.RootGroup(), []iam.Subject{iam.UserSubject(userID)}, role)
	if !s.writeOpResult(w, res, err) {
		return
	}
	noContent(w)
}
