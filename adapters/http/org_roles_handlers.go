package authhttp

import (
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

func (s *Service) handleOrgRolesGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	if orgSlug == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, _, isOwner, err := s.requireOrgOwner(r.Context(), claims.UserID, orgSlug)
	if err != nil {
		if err == core.ErrOrgNotFound {
			notFound(w, "org_not_found")
			return
		}
		serverErr(w, "org_lookup_failed")
		return
	}
	if !isOwner {
		forbidden(w, "forbidden")
		return
	}
	roles, err := s.svc.ListOrgDefinedRoles(r.Context(), canonical)
	if err != nil {
		serverErr(w, "org_roles_lookup_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

func (s *Service) handleOrgRolesPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	if orgSlug == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, _, isOwner, err := s.requireOrgOwner(r.Context(), claims.UserID, orgSlug)
	if err != nil {
		if err == core.ErrOrgNotFound {
			notFound(w, "org_not_found")
			return
		}
		serverErr(w, "org_lookup_failed")
		return
	}
	if !isOwner {
		forbidden(w, "forbidden")
		return
	}
	var body struct {
		Role string `json:"role"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Role) == "" {
		badRequest(w, "invalid_request")
		return
	}
	if err := s.svc.DefineRole(r.Context(), canonical, body.Role); err != nil {
		badRequest(w, "define_role_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Service) handleOrgRolesDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	if orgSlug == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, _, isOwner, err := s.requireOrgOwner(r.Context(), claims.UserID, orgSlug)
	if err != nil {
		if err == core.ErrOrgNotFound {
			notFound(w, "org_not_found")
			return
		}
		serverErr(w, "org_lookup_failed")
		return
	}
	if !isOwner {
		forbidden(w, "forbidden")
		return
	}
	var body struct {
		Role string `json:"role"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Role) == "" {
		badRequest(w, "invalid_request")
		return
	}
	if err := s.svc.DeleteRole(r.Context(), canonical, body.Role); err != nil {
		if err == core.ErrProtectedOrgRole {
			badRequest(w, "protected_role")
			return
		}
		badRequest(w, "delete_role_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}
