package authhttp

import (
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

func (s *Service) handleOrgMembersGET(w http.ResponseWriter, r *http.Request) {
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
	canonical, gateOK := s.requireOrgPermissionGin(w, r, claims, orgSlug, core.PermOrgMembersRead)
	if !gateOK {
		return
	}
	members, err := s.svc.ListOrgMembers(r.Context(), canonical)
	if err != nil {
		serverErr(w, ErrOrgMembershipsLookupFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": members})
}

func (s *Service) handleOrgMembersPOST(w http.ResponseWriter, r *http.Request) {
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
	canonical, gateOK := s.requireOrgPermissionGin(w, r, claims, orgSlug, core.PermOrgMembersCreate)
	if !gateOK {
		return
	}
	var body struct {
		UserID string `json:"user_id"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.UserID) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err := s.svc.AddMember(r.Context(), canonical, strings.TrimSpace(body.UserID)); err != nil {
		badRequest(w, ErrAddMemberFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Service) handleOrgMembersDELETE(w http.ResponseWriter, r *http.Request) {
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
	targetUserID := strings.TrimSpace(r.PathValue("user_id"))
	if targetUserID == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	canonical, gateOK := s.requireOrgPermissionGin(w, r, claims, orgSlug, core.PermOrgMembersDelete)
	if !gateOK {
		return
	}
	if err := s.svc.RemoveMember(r.Context(), canonical, targetUserID); err != nil {
		if err == core.ErrPersonalOrgOwner {
			badRequest(w, ErrCannotRemovePersonalOrgOwner)
			return
		}
		if err == core.ErrLastOrgOwner {
			badRequest(w, ErrCannotRemoveLastOwner)
			return
		}
		badRequest(w, ErrRemoveMemberFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}
