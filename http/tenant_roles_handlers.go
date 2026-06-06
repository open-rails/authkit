package authhttp

import (
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

func (s *Service) handleTenantRolesGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	tenantSlug := strings.TrimSpace(r.PathValue("tenant"))
	if tenantSlug == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, gateOK := s.requireTenantPermissionGin(w, r, claims, tenantSlug, core.PermTenantRead)
	if !gateOK {
		return
	}
	roles, err := s.svc.ListOrgDefinedRoles(r.Context(), canonical)
	if err != nil {
		serverErr(w, "tenant_roles_lookup_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

func (s *Service) handleTenantRolesDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	tenantSlug := strings.TrimSpace(r.PathValue("tenant"))
	role := strings.TrimSpace(r.PathValue("role"))
	if tenantSlug == "" || role == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, gateOK := s.requireTenantPermissionGin(w, r, claims, tenantSlug, core.PermTenantRolesManage)
	if !gateOK {
		return
	}
	if err := s.svc.DeleteRole(r.Context(), canonical, role); err != nil {
		if err == core.ErrProtectedTenantRole {
			badRequest(w, "protected_role")
			return
		}
		badRequest(w, "delete_role_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}
