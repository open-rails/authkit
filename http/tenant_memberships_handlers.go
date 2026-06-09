package authhttp

import (
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

func (s *Service) handleTenantMembersGET(w http.ResponseWriter, r *http.Request) {
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
	members, err := s.svc.ListTenantMembers(r.Context(), canonical)
	if err != nil {
		serverErr(w, "tenant_memberships_lookup_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": members})
}

func (s *Service) handleTenantMembersPOST(w http.ResponseWriter, r *http.Request) {
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
	canonical, gateOK := s.requireTenantPermissionGin(w, r, claims, tenantSlug, core.PermTenantMembersManage)
	if !gateOK {
		return
	}
	var body struct {
		UserID string `json:"user_id"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.UserID) == "" {
		badRequest(w, "invalid_request")
		return
	}
	if err := s.svc.AddMember(r.Context(), canonical, strings.TrimSpace(body.UserID)); err != nil {
		badRequest(w, "add_member_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Service) handleTenantMembersDELETE(w http.ResponseWriter, r *http.Request) {
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
	targetUserID := strings.TrimSpace(r.PathValue("user_id"))
	if targetUserID == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, gateOK := s.requireTenantPermissionGin(w, r, claims, tenantSlug, core.PermTenantMembersManage)
	if !gateOK {
		return
	}
	if err := s.svc.RemoveMember(r.Context(), canonical, targetUserID); err != nil {
		if err == core.ErrPersonalTenantOwner {
			badRequest(w, "cannot_remove_personal_tenant_owner")
			return
		}
		if err == core.ErrLastTenantOwner {
			badRequest(w, "cannot_remove_last_owner")
			return
		}
		badRequest(w, "remove_member_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}
