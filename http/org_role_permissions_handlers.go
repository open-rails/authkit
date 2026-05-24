package authhttp

import (
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

// Org RBAC management endpoints (authkit #46). Roles are sets of permissions;
// authkit stores them opaquely and validates against the catalog (its base
// `org:` permissions UNION the app-declared catalog). Management is gated by the
// base permissions: org:roles:manage to edit a role's permissions, org:read to
// view. owner holds `*` (all) so it passes; a platform global admin bypasses.

// handlePermissionCatalogGET returns the full permission catalog (base + app).
// Any authenticated user may read it (it's just the vocabulary).
func (s *Service) handlePermissionCatalogGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"permissions": s.svc.Catalog()})
}

func (s *Service) handleOrgRolePermissionsGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || claims.IsService() {
		unauthorized(w, "unauthorized")
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	role := strings.TrimSpace(r.PathValue("role"))
	if orgSlug == "" || role == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, gateOK := s.requireOrgPermissionGin(w, r, claims, orgSlug, core.PermOrgRead)
	if !gateOK {
		return
	}
	perms, err := s.svc.GetRolePermissions(r.Context(), canonical, role)
	if err != nil {
		serverErr(w, "role_permissions_lookup_failed")
		return
	}
	if perms == nil {
		perms = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"role": role, "permissions": perms})
}

func (s *Service) handleOrgRolePermissionsPUT(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || claims.IsService() {
		unauthorized(w, "unauthorized")
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	role := strings.TrimSpace(r.PathValue("role"))
	if orgSlug == "" || role == "" {
		badRequest(w, "invalid_request")
		return
	}
	var body struct {
		Permissions []string `json:"permissions"`
	}
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, "invalid_request")
		return
	}
	canonical, gateOK := s.requireOrgPermissionGin(w, r, claims, orgSlug, core.PermOrgRolesManage)
	if !gateOK {
		return
	}
	// NO-ESCALATION + catalog validation: every permission must be defined and
	// within the assigner's own effective permissions.
	actorAll := claimsHasGlobalAdmin(claims)
	unknown, offending, err := s.svc.ValidateGrant(r.Context(), canonical, claims.UserID, body.Permissions, actorAll)
	if err != nil {
		serverErr(w, "permission_validate_failed")
		return
	}
	if len(unknown) > 0 {
		sendErrData(w, http.StatusBadRequest, "unknown_permission", map[string]any{"unknown_permissions": unknown})
		return
	}
	if len(offending) > 0 {
		sendErrData(w, http.StatusForbidden, "permission_grant_denied", map[string]any{"offending_permissions": offending})
		return
	}
	if err := s.svc.SetRolePermissions(r.Context(), canonical, role, body.Permissions); err != nil {
		if err == core.ErrInvalidOrgRole {
			notFound(w, "role_not_found")
			return
		}
		serverErr(w, "role_permissions_update_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Service) handleOrgMemberPermissionsGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || claims.IsService() {
		unauthorized(w, "unauthorized")
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	targetUserID := strings.TrimSpace(r.PathValue("user_id"))
	if orgSlug == "" || targetUserID == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, gateOK := s.requireOrgPermissionGin(w, r, claims, orgSlug, core.PermOrgRead)
	if !gateOK {
		return
	}
	perms, err := s.svc.EffectivePermissions(r.Context(), canonical, targetUserID)
	if err != nil {
		serverErr(w, "member_permissions_lookup_failed")
		return
	}
	if perms == nil {
		perms = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"permissions": perms})
}
