package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	core "github.com/open-rails/authkit/core"
)

// remoteApplicationRegistration is the wire shape posted to register/update a
// remote_application (federation principal, #74). Also the GET response shape.
type remoteApplicationRegistration struct {
	Slug    string `json:"slug"`
	Issuer  string `json:"issuer"`
	OrgID   string `json:"org_id,omitempty"` // owning org (#77)
	JWKSURI string `json:"jwks_uri,omitempty"`
	// Mode selects the trust source: "jwks" (fetch keys from jwks_uri; preferred)
	// XOR "static" (human-managed public_keys list). Empty infers from which
	// field is set. Setting BOTH is rejected — one trust source per principal.
	Mode           string              `json:"mode,omitempty"`
	PublicKeys     []core.RemoteAppKey `json:"public_keys,omitempty"`
	Audiences      []string            `json:"audiences,omitempty"`
	AllowedOrigins []string            `json:"allowed_origins,omitempty"`
	Enabled        *bool               `json:"enabled,omitempty"`
}

type remoteApplicationResponse struct {
	Slug           string              `json:"slug"`
	Issuer         string              `json:"issuer"`
	OrgID          string              `json:"org_id,omitempty"`
	JWKSURI        string              `json:"jwks_uri,omitempty"`
	Mode           string              `json:"mode"`
	PublicKeys     []core.RemoteAppKey `json:"public_keys,omitempty"`
	Audiences      []string            `json:"audiences"`
	AllowedOrigins []string            `json:"allowed_origins"`
	Enabled        bool                `json:"enabled"`
}

func remoteApplicationView(ra core.RemoteApplication) remoteApplicationResponse {
	audiences := ra.Audiences
	if audiences == nil {
		audiences = []string{}
	}
	allowedOrigins := ra.AllowedOrigins
	if allowedOrigins == nil {
		allowedOrigins = []string{}
	}
	return remoteApplicationResponse{
		Slug:           ra.Slug,
		Issuer:         ra.Issuer,
		OrgID:          ra.OrgID,
		JWKSURI:        ra.JWKSURI,
		Mode:           ra.Mode,
		PublicKeys:     ra.PublicKeys,
		Audiences:      audiences,
		AllowedOrigins: allowedOrigins,
		Enabled:        ra.Enabled,
	}
}

// handleRemoteApplicationRegisterPOST registers or updates a remote_application.
// Authorization: global admin for any issuer, otherwise org RBAC for org-owned
// issuers. Unowned issuers are bootstrap/operator-managed and global-admin only.
func (s *Service) handleRemoteApplicationRegisterPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	var body remoteApplicationRegistration
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, "invalid_request")
		return
	}
	if strings.TrimSpace(body.Slug) == "" || strings.TrimSpace(body.Issuer) == "" {
		badRequest(w, "invalid_request")
		return
	}
	if _, err := core.NormalizeRemoteAppTrustSource(body.JWKSURI, body.Mode, body.PublicKeys); err != nil {
		badRequest(w, "invalid_trust_source")
		return
	}
	if _, err := core.NormalizeAllowedOrigins(body.AllowedOrigins); err != nil {
		badRequest(w, "invalid_allowed_origins")
		return
	}
	orgID, ok, err := s.canManageRemoteApplicationByIssuer(r.Context(), claims, body.Issuer, body.OrgID)
	if err != nil {
		serverErr(w, "remote_application_lookup_failed")
		return
	}
	if !ok {
		forbidden(w, "forbidden")
		return
	}

	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	ra, err := s.svc.UpsertRemoteApplication(r.Context(), core.RemoteApplication{
		Slug:           body.Slug,
		OrgID:          orgID,
		Issuer:         body.Issuer,
		JWKSURI:        body.JWKSURI,
		Mode:           body.Mode,
		PublicKeys:     body.PublicKeys,
		Audiences:      body.Audiences,
		AllowedOrigins: body.AllowedOrigins,
		Enabled:        enabled,
	})
	if err != nil {
		if err == core.ErrInvalidRemoteApplication {
			badRequest(w, "invalid_request")
			return
		}
		serverErr(w, "remote_application_register_failed")
		return
	}

	// Make the newly-trusted principal immediately usable.
	if s.verifier != nil && ra.Enabled {
		_ = s.verifier.AddIssuer(ra.Issuer, nil, remoteAppOptions(*ra))
	}
	writeJSON(w, http.StatusOK, remoteApplicationView(*ra))
}

// handleRemoteApplicationsListGET lists remote_applications. Global-admin only.
func (s *Service) handleRemoteApplicationsListGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	items, err := s.svc.ListRemoteApplications(r.Context(), false)
	if err != nil {
		serverErr(w, "remote_application_list_failed")
		return
	}
	out := make([]remoteApplicationResponse, 0, len(items))
	for _, ra := range items {
		out = append(out, remoteApplicationView(ra))
	}
	writeJSON(w, http.StatusOK, map[string]any{"remote_applications": out})
}

// handleRemoteApplicationDeleteDELETE removes a remote_application registration.
// Authorized by global admin, or by org RBAC for org-owned issuers.
func (s *Service) handleRemoteApplicationDeleteDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	var body remoteApplicationRegistration
	_ = decodeJSON(r, &body)
	issuer := strings.TrimSpace(body.Issuer)
	if issuer == "" {
		badRequest(w, "invalid_request")
		return
	}
	_, ok, err := s.canManageRemoteApplicationByIssuer(r.Context(), claims, issuer, "")
	if err != nil {
		serverErr(w, "remote_application_lookup_failed")
		return
	}
	if !ok {
		forbidden(w, "forbidden")
		return
	}
	if err := s.svc.DeleteRemoteApplication(r.Context(), issuer); err != nil {
		if err == core.ErrRemoteApplicationNotFound {
			notFound(w, "remote_application_not_found")
			return
		}
		serverErr(w, "remote_application_delete_failed")
		return
	}
	if s.verifier != nil {
		s.verifier.RemoveIssuer(issuer)
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// remoteApplicationMembershipRequest assigns a remote_application a role on a
// org via the shared membership machinery (#74).
type remoteApplicationMembershipRequest struct {
	Org  string `json:"org"`
	Role string `json:"role,omitempty"`
}

// handleRemoteApplicationMembershipPOST binds a remote_application as a member of
// a org with a role. Authorized: the caller must be able to manage BOTH the
// remote_application owner org and the target org, or be a global admin.
func (s *Service) handleRemoteApplicationMembershipPOST(w http.ResponseWriter, r *http.Request) {
	claims, ra, ok := s.authRemoteApplicationBySlug(w, r)
	if !ok {
		return
	}
	var body remoteApplicationMembershipRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Org) == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, ok, err := s.canManageOrgMembership(r.Context(), claims, body.Org)
	if err != nil {
		if err == core.ErrOrgNotFound {
			notFound(w, "org_not_found")
			return
		}
		serverErr(w, "org_lookup_failed")
		return
	}
	if !ok {
		forbidden(w, "forbidden")
		return
	}
	role := strings.TrimSpace(body.Role)
	if role == "" {
		role = "member"
	}
	if err := s.svc.AddRemoteApplicationMember(r.Context(), canonical, ra.ID, role); err != nil {
		if err == core.ErrInvalidOrgRole {
			badRequest(w, "invalid_role")
			return
		}
		serverErr(w, "remote_application_membership_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"org": canonical, "role": role})
}

// handleRemoteApplicationMembershipDELETE removes a remote_application's
// membership in a org.
func (s *Service) handleRemoteApplicationMembershipDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ra, ok := s.authRemoteApplicationBySlug(w, r)
	if !ok {
		return
	}
	var body remoteApplicationMembershipRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Org) == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, ok, err := s.canManageOrgMembership(r.Context(), claims, body.Org)
	if err != nil {
		if err == core.ErrOrgNotFound {
			notFound(w, "org_not_found")
			return
		}
		serverErr(w, "org_lookup_failed")
		return
	}
	if !ok {
		forbidden(w, "forbidden")
		return
	}
	if err := s.svc.RemoveRemoteApplicationMember(r.Context(), canonical, ra.ID); err != nil {
		serverErr(w, "remote_application_membership_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// ---------------------------------------------------------------------------
// Direct permission grants (#76) — STORED authority for a JWKS self-token
// ---------------------------------------------------------------------------

// remoteApplicationPermissionRequest assigns/removes a direct permission on a
// remote_application principal (#76).
type remoteApplicationPermissionRequest struct {
	Permission string `json:"permission"`
}

// handleRemoteApplicationPermissionsGET lists a remote_application's DIRECT
// permission grants. Authorized by its owner org or a global admin.
func (s *Service) handleRemoteApplicationPermissionsGET(w http.ResponseWriter, r *http.Request) {
	_, ra, ok := s.authRemoteApplicationBySlug(w, r)
	if !ok {
		return
	}
	perms, err := s.svc.ListRemoteApplicationPermissions(r.Context(), ra.ID)
	if err != nil {
		serverErr(w, "remote_application_permissions_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"permissions": perms})
}

// handleRemoteApplicationPermissionPOST grants a direct permission to a
// remote_application. Authorized by its owner org or a global admin.
func (s *Service) handleRemoteApplicationPermissionPOST(w http.ResponseWriter, r *http.Request) {
	claims, ra, ok := s.authRemoteApplicationBySlug(w, r)
	if !ok {
		return
	}
	var body remoteApplicationPermissionRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Permission) == "" {
		badRequest(w, "invalid_request")
		return
	}
	// NO-ESCALATION (#94): the remote-app DIRECT-grant path must run the same
	// catalog + no-escalation check as every other grant path (role-perm set,
	// member-role assign, API-key mint). Resolve against the remote-app's
	// OWNING org. A global admin bypasses (actorAll). Closes the documented
	// gap where any remote-app manager could grant ANY catalog perm — incl.
	// perms the grantor lacks — letting the remote-app act with escalated
	// authority.
	if !claimsHasGlobalAdmin(claims) {
		org, oerr := s.svc.ResolveOrgByID(r.Context(), strings.TrimSpace(ra.OrgID))
		if oerr != nil {
			serverErr(w, "remote_application_org_lookup_failed")
			return
		}
		unknown, offending, verr := s.svc.ValidateGrant(r.Context(), org.Slug, claims.UserID, []string{body.Permission}, false)
		if verr != nil {
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
	}
	if err := s.svc.AddRemoteApplicationPermission(r.Context(), ra.ID, body.Permission); err != nil {
		if err == core.ErrUnknownPermission {
			badRequest(w, "invalid_request")
			return
		}
		serverErr(w, "remote_application_permission_grant_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"permission": strings.TrimSpace(body.Permission)})
}

// handleRemoteApplicationPermissionDELETE revokes a direct permission from a
// remote_application. Authorized by its owner org or a global admin.
func (s *Service) handleRemoteApplicationPermissionDELETE(w http.ResponseWriter, r *http.Request) {
	_, ra, ok := s.authRemoteApplicationBySlug(w, r)
	if !ok {
		return
	}
	var body remoteApplicationPermissionRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Permission) == "" {
		badRequest(w, "invalid_request")
		return
	}
	removed, err := s.svc.RemoveRemoteApplicationPermission(r.Context(), ra.ID, body.Permission)
	if err != nil {
		serverErr(w, "remote_application_permission_revoke_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": removed})
}

// ---------------------------------------------------------------------------
// Attribute definition registry (#75)
// ---------------------------------------------------------------------------

type attributeDefRequest struct {
	Key        string          `json:"key"`
	Version    int32           `json:"version,omitempty"`
	Definition json.RawMessage `json:"definition"`
}

func attributeDefView(d core.RemoteAppAttributeDef) map[string]any {
	return map[string]any{"key": d.Key, "version": d.Version, "definition": d.Definition}
}

// handleAttributeDefPutPOST registers/updates an opaque attribute definition for
// the remote_application (REFERENCE-mode write side, #75). Authorized by either
// the remote_application itself or by the owner org/admin management path.
func (s *Service) handleAttributeDefPutPOST(w http.ResponseWriter, r *http.Request) {
	ra, ok := s.authRemoteApplicationAttributeDefWriter(w, r)
	if !ok {
		return
	}
	var body attributeDefRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Key) == "" {
		badRequest(w, "invalid_request")
		return
	}
	d, err := s.svc.RegisterRemoteAppAttributeDef(r.Context(), ra.ID, body.Key, body.Version, body.Definition)
	if err != nil {
		if err == core.ErrInvalidAttributeDef {
			badRequest(w, "invalid_definition")
			return
		}
		serverErr(w, "attribute_def_register_failed")
		return
	}
	writeJSON(w, http.StatusOK, attributeDefView(*d))
}

// handleAttributeDefGET resolves a definition by (remote_application, key
// [, version]) — the read side a platform uses to hydrate a token reference.
// version query param, when absent, resolves the latest. Authorized for any
// authenticated caller (platforms resolve references they were handed).
func (s *Service) handleAttributeDefGET(w http.ResponseWriter, r *http.Request) {
	_, ok := ClaimsFromContext(r.Context())
	if !ok {
		unauthorized(w, "unauthorized")
		return
	}
	slug := strings.TrimSpace(r.PathValue("slug"))
	key := strings.TrimSpace(r.URL.Query().Get("key"))
	if slug == "" || key == "" {
		badRequest(w, "invalid_request")
		return
	}
	ra, err := s.svc.GetRemoteApplicationBySlug(r.Context(), slug)
	if err != nil {
		notFound(w, "remote_application_not_found")
		return
	}
	var version int32
	if v := strings.TrimSpace(r.URL.Query().Get("version")); v != "" {
		n, perr := strconv.Atoi(v)
		if perr != nil {
			badRequest(w, "invalid_version")
			return
		}
		version = int32(n)
	}
	d, err := s.svc.ResolveRemoteAppAttributeDef(r.Context(), ra.ID, key, version)
	if err != nil {
		if err == core.ErrAttributeDefNotFound {
			notFound(w, "attribute_def_not_found")
			return
		}
		serverErr(w, "attribute_def_resolve_failed")
		return
	}
	writeJSON(w, http.StatusOK, attributeDefView(*d))
}

// ---------------------------------------------------------------------------
// Authorization helpers
// ---------------------------------------------------------------------------

// canManageRemoteApplicationByIssuer reports whether the caller may register or
// mutate the remote_application with the given issuer, and returns the org_id to
// persist. A global admin may manage any. Non-admin callers may only manage
// org-owned issuers for orgs where they hold org:remote_applications:manage.
// Unowned issuers are bootstrap/operator-managed and global-admin only.
func (s *Service) canManageRemoteApplicationByIssuer(ctx context.Context, claims Claims, issuer, requestedOrgID string) (orgID string, ok bool, err error) {
	existing, gerr := s.svc.GetRemoteApplication(ctx, issuer)
	if gerr != nil && gerr != core.ErrRemoteApplicationNotFound {
		return "", false, gerr
	}
	if claimsHasGlobalAdmin(claims) {
		if existing != nil {
			return strings.TrimSpace(requestedOrgID), true, nil
		}
		return strings.TrimSpace(requestedOrgID), true, nil
	}
	if existing != nil {
		orgID = strings.TrimSpace(existing.OrgID)
		if orgID == "" {
			return "", false, nil
		}
		return s.canManageRemoteApplicationOrg(ctx, claims, orgID)
	}
	orgID = strings.TrimSpace(requestedOrgID)
	if orgID == "" {
		return "", false, nil
	}
	return s.canManageRemoteApplicationOrg(ctx, claims, orgID)
}

// authRemoteApplicationBySlug resolves the {slug} path principal and checks
// org-owner/admin authorization. It writes the error response and
// returns ok=false on any failure.
func (s *Service) authRemoteApplicationBySlug(w http.ResponseWriter, r *http.Request) (Claims, *core.RemoteApplication, bool) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return Claims{}, nil, false
	}
	slug := strings.TrimSpace(r.PathValue("slug"))
	if slug == "" {
		badRequest(w, "invalid_request")
		return Claims{}, nil, false
	}
	ra, err := s.svc.GetRemoteApplicationBySlug(r.Context(), slug)
	if err != nil {
		notFound(w, "remote_application_not_found")
		return Claims{}, nil, false
	}
	if !claimsHasGlobalAdmin(claims) {
		orgID := strings.TrimSpace(ra.OrgID)
		if orgID == "" {
			forbidden(w, "forbidden")
			return Claims{}, nil, false
		}
		_, ok, err := s.canManageRemoteApplicationOrg(r.Context(), claims, orgID)
		if err != nil {
			serverErr(w, "remote_application_owner_lookup_failed")
			return Claims{}, nil, false
		}
		if !ok {
			forbidden(w, "forbidden")
			return Claims{}, nil, false
		}
	}
	return claims, ra, true
}

// authRemoteApplicationAttributeDefWriter authorizes writes to the opaque
// attribute-definition registry. Unlike trust/membership/permission management,
// a remote_application may write definitions for itself because those
// definitions are its own delegated-token contract. It may not write another
// remote_application's definitions.
func (s *Service) authRemoteApplicationAttributeDefWriter(w http.ResponseWriter, r *http.Request) (*core.RemoteApplication, bool) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		unauthorized(w, "unauthorized")
		return nil, false
	}
	slug := strings.TrimSpace(r.PathValue("slug"))
	if slug == "" {
		badRequest(w, "invalid_request")
		return nil, false
	}
	ra, err := s.svc.GetRemoteApplicationBySlug(r.Context(), slug)
	if err != nil {
		notFound(w, "remote_application_not_found")
		return nil, false
	}
	if claims.IsRemoteApplication() {
		if strings.TrimSpace(claims.RemoteApplicationID) == strings.TrimSpace(ra.ID) {
			return ra, true
		}
		forbidden(w, "forbidden")
		return nil, false
	}
	if strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return nil, false
	}
	if !claimsHasGlobalAdmin(claims) {
		orgID := strings.TrimSpace(ra.OrgID)
		if orgID == "" {
			forbidden(w, "forbidden")
			return nil, false
		}
		_, ok, err := s.canManageRemoteApplicationOrg(r.Context(), claims, orgID)
		if err != nil {
			serverErr(w, "remote_application_owner_lookup_failed")
			return nil, false
		}
		if !ok {
			forbidden(w, "forbidden")
			return nil, false
		}
	}
	return ra, true
}

func (s *Service) canManageRemoteApplicationOrg(ctx context.Context, claims Claims, orgID string) (string, bool, error) {
	org, err := s.svc.ResolveOrgByID(ctx, strings.TrimSpace(orgID))
	if err != nil {
		return "", false, err
	}
	if claimsHasGlobalAdmin(claims) {
		return org.ID, true, nil
	}
	if strings.TrimSpace(claims.UserID) == "" {
		return "", false, nil
	}
	ok, err := s.svc.HasPermission(ctx, org.Slug, claims.UserID, core.PermOrgRemoteAppsUpdate)
	if err != nil {
		return "", false, err
	}
	if !ok {
		return "", false, nil
	}
	return org.ID, true, nil
}

// canManageOrgMembership reports whether the caller may assign memberships on
// a org: a global admin, or a caller with org remote-application management
// authority. Returns the canonical slug.
func (s *Service) canManageOrgMembership(ctx context.Context, claims Claims, orgSlug string) (canonical string, ok bool, err error) {
	if claimsHasGlobalAdmin(claims) {
		org, e := s.svc.ResolveOrgBySlug(ctx, orgSlug)
		if e != nil {
			return "", false, e
		}
		return org.Slug, true, nil
	}
	return s.requireOrgPermission(ctx, claims, orgSlug, core.PermOrgRemoteAppsUpdate)
}

func claimsHasGlobalAdmin(claims Claims) bool {
	for _, r := range claims.GlobalRoles {
		if strings.EqualFold(strings.TrimSpace(r), "admin") {
			return true
		}
	}
	return false
}
