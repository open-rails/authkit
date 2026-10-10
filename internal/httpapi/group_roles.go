package httpapi

// Role handlers of the group surface: the roles a group can assign, and the
// custom roles it defines (#448).

import (
	"net/http"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/helpers/auth"
)

// groupRolesList returns the roles assignable in the group: those its
// persona declares, then its custom roles.
func (s *Service) groupRolesList(w http.ResponseWriter, r *http.Request, g iam.Group) {
	roles, err := s.svc.ListGroupRoles(r.Context(), iam.GroupByID(g.ID))
	if err != nil {
		writeError(w, err)
		return
	}
	all(w, roles)
}

func (s *Service) groupRoleGet(w http.ResponseWriter, r *http.Request, g iam.Group) {
	role, ok := pathRole(w, r, g)
	if !ok {
		return
	}
	out, err := s.svc.GroupRole(r.Context(), iam.GroupByID(g.ID), role)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) groupRoleCreate(w http.ResponseWriter, r *http.Request, g iam.Group, who auth.Identity) {
	var body GroupRoleCreateRequest
	if err := decodeJSON(r, &body); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	out, err := s.svc.CreateGroupRole(r.Context(), who, iam.GroupByID(g.ID), iam.NewGroupRole{Name: body.Name, Permissions: ident.Perms(body.Permissions)})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Service) groupRoleUpdate(w http.ResponseWriter, r *http.Request, g iam.Group, who auth.Identity) {
	role, ok := pathRole(w, r, g)
	if !ok {
		return
	}
	var body GroupRoleUpdateRequest
	if err := decodeJSON(r, &body); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	out, err := s.svc.UpdateGroupRole(r.Context(), who, iam.GroupByID(g.ID), role, iam.GroupRoleUpdate{Permissions: ident.Perms(body.Permissions)})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// groupRoleDelete deletes a custom role; like every DELETE it is idempotent.
func (s *Service) groupRoleDelete(w http.ResponseWriter, r *http.Request, g iam.Group, who auth.Identity) {
	role, ok := pathRole(w, r, g)
	if !ok {
		return
	}
	if err := s.svc.DeleteGroupRole(r.Context(), who, iam.GroupByID(g.ID), role); err != nil {
		writeError(w, err)
		return
	}
	noContent(w)
}

// pathRole reads {role}, role text of the group's persona; anything else is
// role_not_found.
func pathRole(w http.ResponseWriter, r *http.Request, g iam.Group) (iam.Role, bool) {
	var role iam.Role
	if err := role.UnmarshalText([]byte(r.PathValue("role"))); err != nil || role.IsZero() || role.Persona() != g.Persona {
		writeError(w, iam.ErrRoleNotFound)
		return iam.Role{}, false
	}
	return role, true
}
