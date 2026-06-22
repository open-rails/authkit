package authhttp

import (
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

func (s *Service) handleOrgMemberRolesGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	targetUserID := strings.TrimSpace(r.PathValue("user_id"))
	if orgSlug == "" || targetUserID == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	canonical, gateOK := s.requireOrgPermissionGin(w, r, claims, orgSlug, core.PermOrgMembersRead)
	if !gateOK {
		return
	}
	roles, err := s.svc.ReadMemberRoles(r.Context(), canonical, targetUserID)
	if err != nil {
		serverErr(w, ErrMemberRolesLookupFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

func (s *Service) handleOrgMemberRolesPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	targetUserID := strings.TrimSpace(r.PathValue("user_id"))
	if orgSlug == "" || targetUserID == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	canonical, gateOK := s.requireOrgPermissionGin(w, r, claims, orgSlug, core.PermOrgMembersUpdate)
	if !gateOK {
		return
	}
	var body struct {
		Role string `json:"role"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Role) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	// NO-ESCALATION: assigning a role grants its permissions, so the assigner
	// must hold every permission the role confers (owner=`org:*` passes).
	// This is what keeps a member with org:members:manage from granting the
	// `owner` role (which is `org:*`) and escalating.
	rolePerms, err := s.svc.EffectiveRolePermissions(r.Context(), canonical, body.Role)
	if err != nil {
		serverErr(w, ErrRolePermissionsLookupFailed)
		return
	}
	if _, offending, verr := s.svc.ValidateGrant(r.Context(), canonical, claims.UserID, rolePerms, false); verr != nil {
		serverErr(w, ErrPermissionValidateFailed)
		return
	} else if len(offending) > 0 {
		sendErrData(w, http.StatusForbidden, ErrRoleExceedsGrantor, map[string]any{"offending_permissions": offending})
		return
	}
	if err := s.svc.AssignRole(r.Context(), canonical, targetUserID, body.Role); err != nil {
		badRequest(w, ErrAssignRoleFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Service) handleOrgMemberRolesDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	targetUserID := strings.TrimSpace(r.PathValue("user_id"))
	if orgSlug == "" || targetUserID == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	canonical, gateOK := s.requireOrgPermissionGin(w, r, claims, orgSlug, core.PermOrgMembersUpdate)
	if !gateOK {
		return
	}
	var body struct {
		Role string `json:"role"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Role) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err := s.svc.UnassignRole(r.Context(), canonical, targetUserID, body.Role); err != nil {
		if err == core.ErrLastOrgOwner {
			badRequest(w, ErrCannotRemoveLastOwner)
			return
		}
		badRequest(w, ErrUnassignRoleFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}
