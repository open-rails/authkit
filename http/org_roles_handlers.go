package authhttp

import (
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

func (s *Service) handleOrgRolesGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	if orgSlug == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	canonical, gateOK := s.requireOrgPermissionGin(w, r, claims, orgSlug, core.PermOrgRolesRead)
	if !gateOK {
		return
	}
	roles, err := s.svc.ListOrgDefinedRoles(r.Context(), canonical)
	if err != nil {
		serverErr(w, ErrOrgRolesLookupFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

func (s *Service) handleOrgRolesDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	role := strings.TrimSpace(r.PathValue("role"))
	if orgSlug == "" || role == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	canonical, gateOK := s.requireOrgPermissionGin(w, r, claims, orgSlug, core.PermOrgRolesDelete)
	if !gateOK {
		return
	}
	if err := s.svc.DeleteRole(r.Context(), canonical, role); err != nil {
		if err == core.ErrProtectedOrgRole {
			badRequest(w, ErrProtectedRole)
			return
		}
		badRequest(w, ErrDeleteRoleFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}
