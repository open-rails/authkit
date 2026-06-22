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

// handleRemoteApplicationRegisterPOST registers or updates a remote_application
// nested under POST /orgs/{org}/remote-applications (#95 — org-nested like
// api-keys). The owning org comes from the PATH, NOT the body; the caller must
// hold org:remote_applications:create on it. Body validation runs before the
// DB gate so malformed requests fail fast without a lookup.
func (s *Service) handleRemoteApplicationRegisterPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	var body remoteApplicationRegistration
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if strings.TrimSpace(body.Slug) == "" || strings.TrimSpace(body.Issuer) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if _, err := core.NormalizeRemoteAppTrustSource(body.JWKSURI, body.Mode, body.PublicKeys); err != nil {
		badRequest(w, ErrInvalidTrustSource)
		return
	}
	if _, err := core.NormalizeAllowedOrigins(body.AllowedOrigins); err != nil {
		badRequest(w, ErrInvalidAllowedOrigins)
		return
	}
	orgID, ok := s.gateOrgRemoteApps(w, r, claims, core.PermOrgRemoteAppsCreate)
	if !ok {
		return
	}
	// Anti-takeover: an issuer is owned by exactly one org. If it already exists
	// under a DIFFERENT org, this org may not re-bind it (the path org is
	// authoritative, never the body).
	if existing, gerr := s.svc.GetRemoteApplication(r.Context(), body.Issuer); gerr == nil && existing != nil {
		if strings.TrimSpace(existing.OrgID) != orgID {
			sendErrData(w, http.StatusConflict, ErrIssuerOwnedByOtherOrg, map[string]any{})
			return
		}
	} else if gerr != nil && gerr != core.ErrRemoteApplicationNotFound {
		serverErr(w, ErrRemoteApplicationLookupFailed)
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
			badRequest(w, ErrInvalidRequest)
			return
		}
		if err == core.ErrReservedIssuer {
			badRequest(w, ErrIssuerReserved)
			return
		}
		serverErr(w, ErrRemoteApplicationRegisterFailed)
		return
	}

	// Make the newly-trusted principal immediately usable.
	if s.verifier != nil && ra.Enabled {
		_ = s.verifier.AddIssuer(ra.Issuer, nil, remoteAppOptions(*ra))
	}
	writeJSON(w, http.StatusOK, remoteApplicationView(*ra))
}

// handleRemoteApplicationDeleteDELETE removes a remote_application registration
// addressed by DELETE /orgs/{org}/remote-applications/{slug} (#95). The caller
// must hold org:remote_applications:delete on {org}, and {slug} must be owned by
// it (a cross-org slug 404s, never revealing existence).
func (s *Service) handleRemoteApplicationDeleteDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	orgID, ok := s.gateOrgRemoteApps(w, r, claims, core.PermOrgRemoteAppsDelete)
	if !ok {
		return
	}
	slug := strings.TrimSpace(r.PathValue("slug"))
	if slug == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	ra, err := s.svc.GetRemoteApplicationBySlug(r.Context(), slug)
	if err != nil || strings.TrimSpace(ra.OrgID) != orgID {
		notFound(w, ErrRemoteApplicationNotFound)
		return
	}
	if err := s.svc.DeleteRemoteApplication(r.Context(), ra.Issuer); err != nil {
		if err == core.ErrRemoteApplicationNotFound {
			notFound(w, ErrRemoteApplicationNotFound)
			return
		}
		serverErr(w, ErrRemoteApplicationDeleteFailed)
		return
	}
	if s.verifier != nil {
		s.verifier.RemoveIssuer(ra.Issuer)
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
// remote_application owner org and the target org (org RBAC on each).
func (s *Service) handleRemoteApplicationMembershipPOST(w http.ResponseWriter, r *http.Request) {
	claims, ra, ok := s.authRemoteApplicationBySlug(w, r)
	if !ok {
		return
	}
	var body remoteApplicationMembershipRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Org) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	canonical, ok, err := s.canManageOrgMembership(r.Context(), claims, body.Org)
	if err != nil {
		if err == core.ErrOrgNotFound {
			notFound(w, ErrOrgNotFound)
			return
		}
		serverErr(w, ErrOrgLookupFailed)
		return
	}
	if !ok {
		forbidden(w, ErrForbidden)
		return
	}
	role := strings.TrimSpace(body.Role)
	if role == "" {
		role = "member"
	}
	// NO-ESCALATION (#94): assigning a role to a remote-app grants it that role's
	// permissions, so the caller must hold every permission the role confers in
	// the target org (owner=`org:*` passes). Without this a caller holding only
	// org:remote_applications:* could grant a remote-app the `owner` role and
	// escalate it past their own authority — the same invariant the member-role,
	// role-perm, api-key, invite, and platform-grant paths enforce.
	rolePerms, perr := s.svc.EffectiveRolePermissions(r.Context(), canonical, role)
	if perr != nil {
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
	if err := s.svc.AddRemoteApplicationMember(r.Context(), canonical, ra.ID, role); err != nil {
		if err == core.ErrInvalidOrgRole {
			badRequest(w, ErrInvalidRole)
			return
		}
		serverErr(w, ErrRemoteApplicationMembershipFailed)
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
		badRequest(w, ErrInvalidRequest)
		return
	}
	canonical, ok, err := s.canManageOrgMembership(r.Context(), claims, body.Org)
	if err != nil {
		if err == core.ErrOrgNotFound {
			notFound(w, ErrOrgNotFound)
			return
		}
		serverErr(w, ErrOrgLookupFailed)
		return
	}
	if !ok {
		forbidden(w, ErrForbidden)
		return
	}
	if err := s.svc.RemoveRemoteApplicationMember(r.Context(), canonical, ra.ID); err != nil {
		serverErr(w, ErrRemoteApplicationMembershipFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
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
		badRequest(w, ErrInvalidRequest)
		return
	}
	d, err := s.svc.RegisterRemoteAppAttributeDef(r.Context(), ra.ID, body.Key, body.Version, body.Definition)
	if err != nil {
		if err == core.ErrInvalidAttributeDef {
			badRequest(w, ErrInvalidDefinition)
			return
		}
		serverErr(w, ErrAttributeDefRegisterFailed)
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
		unauthorized(w, ErrUnauthorized)
		return
	}
	slug := strings.TrimSpace(r.PathValue("slug"))
	key := strings.TrimSpace(r.URL.Query().Get("key"))
	if slug == "" || key == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	ra, err := s.svc.GetRemoteApplicationBySlug(r.Context(), slug)
	if err != nil {
		notFound(w, ErrRemoteApplicationNotFound)
		return
	}
	var version int32
	if v := strings.TrimSpace(r.URL.Query().Get("version")); v != "" {
		n, perr := strconv.Atoi(v)
		if perr != nil {
			badRequest(w, ErrInvalidVersion)
			return
		}
		version = int32(n)
	}
	d, err := s.svc.ResolveRemoteAppAttributeDef(r.Context(), ra.ID, key, version)
	if err != nil {
		if err == core.ErrAttributeDefNotFound {
			notFound(w, ErrAttributeDefNotFound)
			return
		}
		serverErr(w, ErrAttributeDefResolveFailed)
		return
	}
	writeJSON(w, http.StatusOK, attributeDefView(*d))
}

// ---------------------------------------------------------------------------
// Authorization helpers
// ---------------------------------------------------------------------------

// gateOrgRemoteApps resolves the {org} path segment, enforces `perm` (an
// org:remote_applications:* permission) on it for the caller, and returns the
// org_id. It writes the standard error response and returns ok=false on any
// failure. This is the shared org-RBAC gate for the org-nested remote-app
// management routes (#95 — register/delete/memberships under /orgs/{org}/...).
func (s *Service) gateOrgRemoteApps(w http.ResponseWriter, r *http.Request, claims Claims, perm string) (orgID string, ok bool) {
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	if orgSlug == "" {
		badRequest(w, ErrInvalidRequest)
		return "", false
	}
	org, err := s.svc.ResolveOrgBySlug(r.Context(), orgSlug)
	if err != nil {
		if err == core.ErrOrgNotFound {
			notFound(w, ErrOrgNotFound)
		} else {
			serverErr(w, ErrOrgLookupFailed)
		}
		return "", false
	}
	allowed, err := s.svc.HasPermission(r.Context(), org.Slug, claims.UserID, perm)
	if err != nil {
		serverErr(w, ErrPermissionCheckFailed)
		return "", false
	}
	if !allowed {
		forbidden(w, ErrForbidden)
		return "", false
	}
	return org.ID, true
}

// authRemoteApplicationBySlug resolves the {org}/{slug} membership-route
// principal: it enforces org:remote_applications:update on the {org} path
// segment (the issuer's OWNING org) and verifies {slug} is owned by it (a
// cross-org slug 404s). It writes the error response and returns ok=false on any
// failure.
func (s *Service) authRemoteApplicationBySlug(w http.ResponseWriter, r *http.Request) (Claims, *core.RemoteApplication, bool) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return Claims{}, nil, false
	}
	orgID, ok := s.gateOrgRemoteApps(w, r, claims, core.PermOrgRemoteAppsUpdate)
	if !ok {
		return Claims{}, nil, false
	}
	slug := strings.TrimSpace(r.PathValue("slug"))
	if slug == "" {
		badRequest(w, ErrInvalidRequest)
		return Claims{}, nil, false
	}
	ra, err := s.svc.GetRemoteApplicationBySlug(r.Context(), slug)
	if err != nil || strings.TrimSpace(ra.OrgID) != orgID {
		notFound(w, ErrRemoteApplicationNotFound)
		return Claims{}, nil, false
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
		unauthorized(w, ErrUnauthorized)
		return nil, false
	}
	slug := strings.TrimSpace(r.PathValue("slug"))
	if slug == "" {
		badRequest(w, ErrInvalidRequest)
		return nil, false
	}
	ra, err := s.svc.GetRemoteApplicationBySlug(r.Context(), slug)
	if err != nil {
		notFound(w, ErrRemoteApplicationNotFound)
		return nil, false
	}
	if claims.IsRemoteApplication() {
		if strings.TrimSpace(claims.RemoteApplicationID) == strings.TrimSpace(ra.ID) {
			return ra, true
		}
		forbidden(w, ErrForbidden)
		return nil, false
	}
	if strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return nil, false
	}
	orgID := strings.TrimSpace(ra.OrgID)
	if orgID == "" {
		forbidden(w, ErrForbidden)
		return nil, false
	}
	if _, ok, err := s.canManageRemoteApplicationOrg(r.Context(), claims, orgID); err != nil {
		serverErr(w, ErrRemoteApplicationOwnerLookupFailed)
		return nil, false
	} else if !ok {
		forbidden(w, ErrForbidden)
		return nil, false
	}
	return ra, true
}

func (s *Service) canManageRemoteApplicationOrg(ctx context.Context, claims Claims, orgID string) (string, bool, error) {
	org, err := s.svc.ResolveOrgByID(ctx, strings.TrimSpace(orgID))
	if err != nil {
		return "", false, err
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
// a org: a caller with org remote-application management authority. Returns the
// canonical slug. There is no cross-org admin bypass — platform-admins manage
// orgs as ENTITIES via /admin/orgs/*, never their internals (#95).
func (s *Service) canManageOrgMembership(ctx context.Context, claims Claims, orgSlug string) (canonical string, ok bool, err error) {
	return s.requireOrgPermission(ctx, claims, orgSlug, core.PermOrgRemoteAppsUpdate)
}
