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

// handleOrgRolePUT is idempotent create-or-replace for a role: it defines the
// role name if absent and sets its permission set in one call (REST resource
// PUT, replacing the old POST /roles + PUT /roles/{role}/permissions pair).
// Gated org:roles:manage with catalog validation + no-escalation. Read the
// result back via GET /orgs/{org}/roles/{role}.
func (s *Service) handleOrgRolePUT(w http.ResponseWriter, r *http.Request) {
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
	canonical, gateOK := s.requireOrgPermissionGin(w, r, claims, orgSlug, core.PermOrgRolesUpdate)
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
	// Create-or-replace: define the role name (no-op if it exists), then set perms.
	if err := s.svc.DefineRole(r.Context(), canonical, role); err != nil {
		if err == core.ErrInvalidOrgRole {
			badRequest(w, "invalid_role")
			return
		}
		serverErr(w, "define_role_failed")
		return
	}
	if err := s.svc.SetRolePermissions(r.Context(), canonical, role, body.Permissions); err != nil {
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
	canonical, gateOK := s.requireOrgPermissionGin(w, r, claims, orgSlug, core.PermOrgMembersRead)
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
