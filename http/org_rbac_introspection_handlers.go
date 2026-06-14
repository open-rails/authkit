package authhttp

import (
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

// Org-RBAC introspection endpoints (authkit #46 follow-up). These complement the
// management endpoints with the read-side primitives every comparable RBAC API
// exposes: self introspection (/me), a permission-check ("can I?") endpoint, and
// a grantable-permission preview. Self endpoints require only org membership (a
// member may always read their OWN roles/permissions, no org:read); the rest are
// gated as noted.

// callerEffectivePermissions resolves the concrete permission set of the CALLER
// in the given (already-canonical) org. A service principal (service token) carries its
// permissions directly in claims; a user's set is computed from role mappings.
func (s *Service) callerEffectivePermissions(r *http.Request, claims Claims, canonicalOrg string) ([]string, error) {
	if claims.IsService() {
		return append([]string{}, claims.Permissions...), nil
	}
	return s.svc.EffectivePermissions(r.Context(), canonicalOrg, claims.UserID)
}

// handleOrgMeGET returns the caller's OWN membership view in the org — roles +
// effective permissions in one call. Requires membership only: a member may
// always introspect itself without holding org:read. A global admin gets the
// full catalog (and no roles, since membership is not required).
func (s *Service) handleOrgMeGET(w http.ResponseWriter, r *http.Request) {
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
	if claimsHasGlobalAdmin(claims) {
		org, err := s.svc.ResolveOrgBySlug(r.Context(), orgSlug)
		if err != nil {
			s.writeOrgLookupErr(w, err)
			return
		}
		names := make([]string, 0)
		for _, d := range s.svc.Catalog() {
			names = append(names, d.Name)
		}
		writeJSON(w, http.StatusOK, map[string]any{"org": org.Slug, "roles": []string{}, "permissions": names})
		return
	}
	canonical, member, err := s.requireOrgMember(r.Context(), claims.UserID, orgSlug)
	if err != nil {
		s.writeOrgLookupErr(w, err)
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
	writeJSON(w, http.StatusOK, map[string]any{"org": canonical, "roles": roles, "permissions": perms})
}

// handleOrgPermissionCheckPOST answers "does the principal hold these
// permissions?" (GCP testIamPermissions / AWS SimulatePrincipalPolicy shape).
// Body: {"permissions":[...]}; returns {"granted":[...]} — the requested subset
// the principal holds. By default the principal is the caller (a member may
// always check itself). An optional "user_id" checks another member and
// requires org:read. A global admin holds everything.
func (s *Service) handleOrgPermissionCheckPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || (strings.TrimSpace(claims.UserID) == "" && !claims.IsService()) {
		unauthorized(w, "unauthorized")
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	if orgSlug == "" {
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
		// Checking another member requires org:read.
		canonical, gateOK := s.requireOrgPermissionGin(w, r, claims, orgSlug, core.PermOrgRead)
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
		// Self-check: caller must be a member of the org.
		canonical, member, err := s.requireOrgMember(r.Context(), claims.UserID, orgSlug)
		if err != nil {
			s.writeOrgLookupErr(w, err)
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

// handleOrgRoleGET returns a single role's detail (name + permission tokens) in
// one call. Gated org:read. 404 if the role is not defined in the org.
func (s *Service) handleOrgRoleGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
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
	defined, err := s.svc.ListOrgDefinedRoles(r.Context(), canonical)
	if err != nil {
		serverErr(w, "org_roles_lookup_failed")
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

// writeOrgLookupErr maps an org-resolution error to the standard response.
func (s *Service) writeOrgLookupErr(w http.ResponseWriter, err error) {
	if err == core.ErrOrgNotFound {
		notFound(w, "org_not_found")
		return
	}
	serverErr(w, "org_lookup_failed")
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
