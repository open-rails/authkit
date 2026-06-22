package authhttp

import (
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

// Org RBAC management endpoints. Roles are sets of permissions; authkit stores
// them opaquely and validates against its base `org:` permissions UNION the
// app-declared permissions.

// handlePermissionsGET returns the full permission set (base + app).
// Any authenticated user may read it (it's just the vocabulary).
func (s *Service) handlePermissionsGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"permissions": s.svc.Permissions()})
}

// handleOrgRolePUT is idempotent create-or-replace for a role: it defines the
// role name if absent and sets its permission set in one call (REST resource
// PUT, replacing the old POST /roles + PUT /roles/{role}/permissions pair).
// Gated by org role update permission with validation + no-escalation. Read the
// result back via GET /orgs/{org}/roles/{role}.
func (s *Service) handleOrgRolePUT(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || claims.IsService() {
		unauthorized(w, ErrUnauthorized)
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	role := strings.TrimSpace(r.PathValue("role"))
	if orgSlug == "" || role == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	var body struct {
		Permissions []string `json:"permissions"`
	}
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	canonical, gateOK := s.requireOrgPermissionGin(w, r, claims, orgSlug, core.PermOrgRolesUpdate)
	if !gateOK {
		return
	}
	// NO-ESCALATION + catalog validation: every permission must be defined and
	// within the assigner's own effective permissions.
	unknown, offending, err := s.svc.ValidateGrant(r.Context(), canonical, claims.UserID, body.Permissions, false)
	if err != nil {
		serverErr(w, ErrPermissionValidateFailed)
		return
	}
	if len(unknown) > 0 {
		sendErrData(w, http.StatusBadRequest, ErrUnknownPermission, map[string]any{"unknown_permissions": unknown})
		return
	}
	if len(offending) > 0 {
		sendErrData(w, http.StatusForbidden, ErrPermissionGrantDenied, map[string]any{"offending_permissions": offending})
		return
	}
	// Create-or-replace: define the role name (no-op if it exists), then set perms.
	if err := s.svc.DefineRole(r.Context(), canonical, role); err != nil {
		if err == core.ErrInvalidOrgRole {
			badRequest(w, ErrInvalidRole)
			return
		}
		serverErr(w, ErrDefineRoleFailed)
		return
	}
	if err := s.svc.SetRolePermissions(r.Context(), canonical, role, body.Permissions); err != nil {
		serverErr(w, ErrRolePermissionsUpdateFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Service) handleOrgMemberPermissionsGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || claims.IsService() {
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
	perms, err := s.svc.EffectivePermissions(r.Context(), canonical, targetUserID)
	if err != nil {
		serverErr(w, ErrMemberPermissionsLookupFailed)
		return
	}
	if perms == nil {
		perms = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"permissions": perms})
}
