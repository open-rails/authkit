package authhttp

import (
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

// Platform RBAC HTTP layer (#95, Layer 2). These are the platform-admin
// endpoints — managing the `platform:` directory plane (platform roles + the
// platform-admin roster). They gate IN-HANDLER on `platform:` permissions via
// requirePlatformPermission; authority comes from either a live platform role
// assigned to a local user or a delegated access token whose concrete
// permissions were already validated against the issuer remote application's
// stored authority. The first super-admin (`platform:*`) is seeded out-of-band
// (bootstrap/manifest), exactly like an org's first `owner`.

// requirePlatformPermission gates a platform-admin endpoint: the caller must
// hold `perm` in the Layer-2 platform plane. Writes the standard error response
// and returns false when not permitted. There is NO org/global-admin bypass —
// the two layers are disjoint, so platform authority is platform-role-only.
func (s *Service) requirePlatformPermission(w http.ResponseWriter, r *http.Request, claims Claims, perm string) bool {
	if claims.IsDelegatedAccessToken() {
		if claims.HasPermission(perm) {
			return true
		}
		forbidden(w, "forbidden")
		return false
	}
	if strings.TrimSpace(claims.UserID) == "" {
		forbidden(w, "forbidden")
		return false
	}
	ok, err := s.svc.HasPlatformPermission(r.Context(), claims.UserID, perm)
	if err != nil {
		serverErr(w, "platform_permission_lookup_failed")
		return false
	}
	if !ok {
		forbidden(w, "forbidden")
		return false
	}
	return true
}

// handlePlatformRolesGET lists every defined platform role. Gate: platform:roles:read.
func (s *Service) handlePlatformRolesGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		unauthorized(w, "unauthorized")
		return
	}
	if !s.requirePlatformPermission(w, r, claims, core.PermPlatformRolesRead) {
		return
	}
	roles, err := s.svc.ListPlatformRoles(r.Context())
	if err != nil {
		serverErr(w, "platform_roles_list_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

// handlePlatformRoleGET returns one platform role's permissions. Gate: platform:roles:read.
func (s *Service) handlePlatformRoleGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		unauthorized(w, "unauthorized")
		return
	}
	role := strings.TrimSpace(r.PathValue("role"))
	if role == "" {
		badRequest(w, "invalid_request")
		return
	}
	if !s.requirePlatformPermission(w, r, claims, core.PermPlatformRolesRead) {
		return
	}
	perms, err := s.svc.GetPlatformRolePermissions(r.Context(), role)
	if err != nil {
		serverErr(w, "platform_role_lookup_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"role": role, "permissions": perms})
}

// handlePlatformRolePUT defines (or replaces the perms of) a platform role.
// Gate: platform:roles:create. NO-ESCALATION + DISJOINT: every permission must
// be a `platform:` perm the caller themselves holds (ValidatePlatformGrant).
func (s *Service) handlePlatformRolePUT(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		unauthorized(w, "unauthorized")
		return
	}
	role := strings.TrimSpace(r.PathValue("role"))
	if role == "" {
		badRequest(w, "invalid_request")
		return
	}
	if !s.requirePlatformPermission(w, r, claims, core.PermPlatformRolesCreate) {
		return
	}
	var body struct {
		Permissions []string `json:"permissions"`
	}
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, "invalid_request")
		return
	}
	unknown, offending, err := s.svc.ValidatePlatformGrant(r.Context(), claims.UserID, body.Permissions, false)
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
	if err := s.svc.DefinePlatformRole(r.Context(), role); err != nil {
		serverErr(w, "platform_role_define_failed")
		return
	}
	if err := s.svc.SetPlatformRolePermissions(r.Context(), role, body.Permissions); err != nil {
		serverErr(w, "platform_role_set_perms_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"role": role, "permissions": body.Permissions})
}

// handlePlatformRoleDELETE deletes a platform role (cascading its perms +
// assignments). Gate: platform:roles:delete.
func (s *Service) handlePlatformRoleDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		unauthorized(w, "unauthorized")
		return
	}
	role := strings.TrimSpace(r.PathValue("role"))
	if role == "" {
		badRequest(w, "invalid_request")
		return
	}
	if !s.requirePlatformPermission(w, r, claims, core.PermPlatformRolesDelete) {
		return
	}
	if _, err := s.svc.DeletePlatformRole(r.Context(), role); err != nil {
		serverErr(w, "platform_role_delete_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// handlePlatformRoleGrantPOST assigns a platform role to a user — minting a
// platform-admin (the most dangerous op). Gate: platform:members:create.
// NO-ESCALATION: the caller must hold every permission the role confers, so a
// limited platform-admin cannot hand out a more powerful role than their own.
func (s *Service) handlePlatformRoleGrantPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		unauthorized(w, "unauthorized")
		return
	}
	role := strings.TrimSpace(r.PathValue("role"))
	if role == "" {
		badRequest(w, "invalid_request")
		return
	}
	if !s.requirePlatformPermission(w, r, claims, core.PermPlatformMembersCreate) {
		return
	}
	var body struct {
		UserID string `json:"user_id"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.UserID) == "" {
		badRequest(w, "invalid_request")
		return
	}
	rolePerms, err := s.svc.GetPlatformRolePermissions(r.Context(), role)
	if err != nil {
		serverErr(w, "platform_role_lookup_failed")
		return
	}
	if _, offending, verr := s.svc.ValidatePlatformGrant(r.Context(), claims.UserID, rolePerms, false); verr != nil {
		serverErr(w, "permission_validate_failed")
		return
	} else if len(offending) > 0 {
		sendErrData(w, http.StatusForbidden, "role_exceeds_grantor", map[string]any{"offending_permissions": offending})
		return
	}
	if err := s.svc.AssignPlatformRole(r.Context(), body.UserID, role); err != nil {
		badRequest(w, "assign_platform_role_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// handlePlatformRoleRevokePOST revokes a platform role from a user.
// Gate: platform:members:delete.
func (s *Service) handlePlatformRoleRevokePOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		unauthorized(w, "unauthorized")
		return
	}
	role := strings.TrimSpace(r.PathValue("role"))
	if role == "" {
		badRequest(w, "invalid_request")
		return
	}
	if !s.requirePlatformPermission(w, r, claims, core.PermPlatformMembersDelete) {
		return
	}
	var body struct {
		UserID string `json:"user_id"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.UserID) == "" {
		badRequest(w, "invalid_request")
		return
	}
	removed, err := s.svc.UnassignPlatformRole(r.Context(), body.UserID, role)
	if err != nil {
		serverErr(w, "revoke_platform_role_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": removed})
}

// handlePlatformRoleMembersGET lists the users holding a platform role (the
// roster). Gate: platform:members:read.
func (s *Service) handlePlatformRoleMembersGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		unauthorized(w, "unauthorized")
		return
	}
	role := strings.TrimSpace(r.PathValue("role"))
	if role == "" {
		badRequest(w, "invalid_request")
		return
	}
	if !s.requirePlatformPermission(w, r, claims, core.PermPlatformMembersRead) {
		return
	}
	members, err := s.svc.PlatformRoleMembers(r.Context(), role)
	if err != nil {
		serverErr(w, "platform_role_members_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"role": role, "members": members})
}

// handleMePlatformPermissionsGET returns the caller's OWN effective platform
// permissions (self introspection; no target → authenticated-only).
func (s *Service) handleMePlatformPermissionsGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	perms, err := s.svc.EffectivePlatformPermissions(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, "platform_permissions_lookup_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"permissions": perms})
}
