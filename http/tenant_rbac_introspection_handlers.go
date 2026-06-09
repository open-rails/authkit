package authhttp

import (
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

// Tenant-RBAC introspection endpoints (authkit #46 follow-up). These complement the
// management endpoints with the read-side primitives every comparable RBAC API
// exposes: self introspection (/me), a permission-check ("can I?") endpoint, and
// a grantable-permission preview. Self endpoints require only tenant membership (a
// member may always read their OWN roles/permissions, no tenant:read); the rest are
// gated as noted.

// callerEffectivePermissions resolves the concrete permission set of the CALLER
// in the given (already-canonical) tenant. A service principal (service token) carries its
// permissions directly in claims; a user's set is computed from role mappings.
func (s *Service) callerEffectivePermissions(r *http.Request, claims Claims, canonicalTenant string) ([]string, error) {
	if claims.IsService() {
		return append([]string{}, claims.Permissions...), nil
	}
	return s.svc.EffectivePermissions(r.Context(), canonicalTenant, claims.UserID)
}

// handleTenantMeGET returns the caller's OWN membership view in the tenant — roles +
// effective permissions in one call. Requires membership only: a member may
// always introspect itself without holding tenant:read. A global admin gets the
// full catalog (and no roles, since membership is not required).
func (s *Service) handleTenantMeGET(w http.ResponseWriter, r *http.Request) {
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
	if claimsHasGlobalAdmin(claims) {
		tenant, err := s.svc.ResolveTenantBySlug(r.Context(), tenantSlug)
		if err != nil {
			s.writeTenantLookupErr(w, err)
			return
		}
		names := make([]string, 0)
		for _, d := range s.svc.Catalog() {
			names = append(names, d.Name)
		}
		writeJSON(w, http.StatusOK, map[string]any{"tenant": tenant.Slug, "roles": []string{}, "permissions": names})
		return
	}
	canonical, member, err := s.requireTenantMember(r.Context(), claims.UserID, tenantSlug)
	if err != nil {
		s.writeTenantLookupErr(w, err)
		return
	}
	if !member {
		forbidden(w, "forbidden")
		return
	}
	roles, err := s.svc.ReadMemberRoles(r.Context(), canonical, claims.UserID)
	if err != nil {
		serverErr(w, "member_roles_lookup_failed")
		return
	}
	perms, err := s.svc.EffectivePermissions(r.Context(), canonical, claims.UserID)
	if err != nil {
		serverErr(w, "member_permissions_lookup_failed")
		return
	}
	if roles == nil {
		roles = []string{}
	}
	if perms == nil {
		perms = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenant": canonical, "roles": roles, "permissions": perms})
}

// handleTenantPermissionCheckPOST answers "does the principal hold these
// permissions?" (GCP testIamPermissions / AWS SimulatePrincipalPolicy shape).
// Body: {"permissions":[...]}; returns {"granted":[...]} — the requested subset
// the principal holds. By default the principal is the caller (a member may
// always check itself). An optional "user_id" checks another member and
// requires tenant:read. A global admin holds everything.
func (s *Service) handleTenantPermissionCheckPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || (strings.TrimSpace(claims.UserID) == "" && !claims.IsService()) {
		unauthorized(w, "unauthorized")
		return
	}
	tenantSlug := strings.TrimSpace(r.PathValue("tenant"))
	if tenantSlug == "" {
		badRequest(w, "invalid_request")
		return
	}
	var body struct {
		Permissions []string `json:"permissions"`
		UserID      string   `json:"user_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, "invalid_request")
		return
	}
	requested := dedupeNonEmpty(body.Permissions)

	var held []string
	target := strings.TrimSpace(body.UserID)
	switch {
	case target != "" && target != claims.UserID:
		// Checking another member requires tenant:read.
		canonical, gateOK := s.requireTenantPermissionGin(w, r, claims, tenantSlug, core.PermTenantRead)
		if !gateOK {
			return
		}
		perms, err := s.svc.EffectivePermissions(r.Context(), canonical, target)
		if err != nil {
			serverErr(w, "member_permissions_lookup_failed")
			return
		}
		held = perms
	case claimsHasGlobalAdmin(claims):
		// Self-check by a global admin: holds everything requested.
		writeJSON(w, http.StatusOK, map[string]any{"granted": requested})
		return
	default:
		// Self-check: caller must be a member of the tenant.
		canonical, member, err := s.requireTenantMember(r.Context(), claims.UserID, tenantSlug)
		if err != nil {
			s.writeTenantLookupErr(w, err)
			return
		}
		if !member && !claims.IsService() {
			forbidden(w, "forbidden")
			return
		}
		perms, err := s.callerEffectivePermissions(r, claims, canonical)
		if err != nil {
			serverErr(w, "member_permissions_lookup_failed")
			return
		}
		held = perms
	}

	heldSet := map[string]bool{}
	for _, p := range held {
		heldSet[p] = true
	}
	granted := make([]string, 0, len(requested))
	for _, p := range requested {
		if heldSet[p] {
			granted = append(granted, p)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"granted": granted})
}

// handleTenantRoleGET returns a single role's detail (name + permission tokens) in
// one call. Gated tenant:read. 404 if the role is not defined in the tenant.
func (s *Service) handleTenantRoleGET(w http.ResponseWriter, r *http.Request) {
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
	canonical, gateOK := s.requireTenantPermissionGin(w, r, claims, tenantSlug, core.PermTenantRead)
	if !gateOK {
		return
	}
	defined, err := s.svc.ListTenantDefinedRoles(r.Context(), canonical)
	if err != nil {
		serverErr(w, "tenant_roles_lookup_failed")
		return
	}
	found := ""
	for _, d := range defined {
		if strings.EqualFold(d, role) {
			found = d
			break
		}
	}
	if found == "" {
		notFound(w, "role_not_found")
		return
	}
	perms, err := s.svc.GetRolePermissions(r.Context(), canonical, found)
	if err != nil {
		serverErr(w, "role_permissions_lookup_failed")
		return
	}
	if perms == nil {
		perms = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"role": found, "permissions": perms})
}

// writeTenantLookupErr maps an tenant-resolution error to the standard response.
func (s *Service) writeTenantLookupErr(w http.ResponseWriter, err error) {
	if err == core.ErrTenantNotFound {
		notFound(w, "tenant_not_found")
		return
	}
	serverErr(w, "tenant_lookup_failed")
}

// dedupeNonEmpty trims, drops empties, and de-duplicates while preserving order.
func dedupeNonEmpty(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
