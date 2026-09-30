package httpapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ops"
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
		writeError(w, err)
		return
	}
	s.groupRolesList(w, g)
}

func (s *Service) handleAdminUserRolePUT(w http.ResponseWriter, r *http.Request) {
	s.adminUserRole(w, r, func(ctx context.Context, a iam.Actor, subject iam.Subject, role iam.Role) error {
		member, err := s.svc.SetGroupRole(ctx, a, iam.RootGroup(), subject, role)
		if err == nil {
			writeJSON(w, http.StatusOK, member)
		}
		return err
	})
}

func (s *Service) handleAdminUserRoleDELETE(w http.ResponseWriter, r *http.Request) {
	s.adminUserRole(w, r, func(ctx context.Context, a iam.Actor, subject iam.Subject, role iam.Role) error {
		err := s.svc.RemoveGroupMember(ctx, a, iam.RootGroup(), subject, ops.IfRole(role))
		if err == nil {
			noContent(w)
		}
		return err
	})
}

// adminUserRole runs op on {user_id} and the root role {role}; op answers its
// success.
func (s *Service) adminUserRole(w http.ResponseWriter, r *http.Request, op func(ctx context.Context, a iam.Actor, subject iam.Subject, role iam.Role) error) {
	actor, ok := verify.ActorFromContext(r.Context())
	if !ok {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	if _, ok := userActorID(w, actor); !ok {
		return
	}
	userID := strings.TrimSpace(r.PathValue("user_id"))
	text := strings.TrimSpace(r.PathValue("role"))
	if userID == "" || text == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	role, err := s.groupRole(iam.RootPersona, text)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := op(r.Context(), actor, iam.UserSubject(userID), role); err != nil {
		writeError(w, err)
	}
}
