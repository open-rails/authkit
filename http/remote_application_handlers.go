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
	JWKSURI string `json:"jwks_uri,omitempty"`
	// Mode selects the trust source: "jwks" (fetch keys from jwks_uri; preferred)
	// XOR "static" (human-managed public_keys list). Empty infers from which
	// field is set. Setting BOTH is rejected — one trust source per principal.
	Mode       string              `json:"mode,omitempty"`
	PublicKeys []core.RemoteAppKey `json:"public_keys,omitempty"`
	Audiences  []string            `json:"audiences,omitempty"`
	Enabled    *bool               `json:"enabled,omitempty"`
}

type remoteApplicationResponse struct {
	Slug       string              `json:"slug"`
	Issuer     string              `json:"issuer"`
	JWKSURI    string              `json:"jwks_uri,omitempty"`
	Mode       string              `json:"mode"`
	PublicKeys []core.RemoteAppKey `json:"public_keys,omitempty"`
	Audiences  []string            `json:"audiences"`
	Enabled    bool                `json:"enabled"`
}

func remoteApplicationView(ra core.RemoteApplication) remoteApplicationResponse {
	audiences := ra.Audiences
	if audiences == nil {
		audiences = []string{}
	}
	return remoteApplicationResponse{
		Slug:       ra.Slug,
		Issuer:     ra.Issuer,
		JWKSURI:    ra.JWKSURI,
		Mode:       ra.Mode,
		PublicKeys: ra.PublicKeys,
		Audiences:  audiences,
		Enabled:    ra.Enabled,
	}
}

// handleRemoteApplicationRegisterPOST registers or updates a remote_application.
// Authorization: a global admin, or (for an existing principal) its
// owner_user_id. A new principal is owned by the registering user.
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
	owner, ok, err := s.canManageRemoteApplicationByIssuer(r.Context(), claims, body.Issuer)
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
		Slug:        body.Slug,
		OwnerUserID: owner,
		Issuer:      body.Issuer,
		JWKSURI:     body.JWKSURI,
		Mode:        body.Mode,
		PublicKeys:  body.PublicKeys,
		Audiences:   body.Audiences,
		Enabled:     enabled,
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
// Authorized by its owner_user_id or a global admin.
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
	_, ok, err := s.canManageRemoteApplicationByIssuer(r.Context(), claims, issuer)
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

// handleRemoteApplicationSubjectsGET lists the delegated subjects a
// remote_application has vouched for. Authorized by its owner or a global admin.
func (s *Service) handleRemoteApplicationSubjectsGET(w http.ResponseWriter, r *http.Request) {
	claims, ra, ok := s.authRemoteApplicationBySlug(w, r)
	if !ok {
		return
	}
	_ = claims
	subjects, err := s.svc.ListRemoteAppSubjects(r.Context(), ra.ID)
	if err != nil {
		serverErr(w, "remote_application_subjects_failed")
		return
	}
	out := make([]map[string]any, 0, len(subjects))
	for _, sub := range subjects {
		out = append(out, map[string]any{
			"issuer":       sub.Issuer,
			"subject":      sub.Subject,
			"created_at":   sub.CreatedAt,
			"last_seen_at": sub.LastSeenAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"subjects": out})
}

// remoteApplicationMembershipRequest assigns a remote_application a role on a
// tenant via the shared membership machinery (#74).
type remoteApplicationMembershipRequest struct {
	Tenant string `json:"tenant"`
	Role   string `json:"role,omitempty"`
}

// handleRemoteApplicationMembershipPOST binds a remote_application as a member of
// a tenant with a role. Authorized: the caller must own BOTH the
// remote_application and the tenant (or be a global admin).
func (s *Service) handleRemoteApplicationMembershipPOST(w http.ResponseWriter, r *http.Request) {
	claims, ra, ok := s.authRemoteApplicationBySlug(w, r)
	if !ok {
		return
	}
	var body remoteApplicationMembershipRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Tenant) == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, ok, err := s.canManageTenantMembership(r.Context(), claims, body.Tenant)
	if err != nil {
		if err == core.ErrTenantNotFound {
			notFound(w, "tenant_not_found")
			return
		}
		serverErr(w, "tenant_lookup_failed")
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
		if err == core.ErrInvalidTenantRole {
			badRequest(w, "invalid_role")
			return
		}
		serverErr(w, "remote_application_membership_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenant": canonical, "role": role})
}

// handleRemoteApplicationMembershipDELETE removes a remote_application's
// membership in a tenant.
func (s *Service) handleRemoteApplicationMembershipDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ra, ok := s.authRemoteApplicationBySlug(w, r)
	if !ok {
		return
	}
	var body remoteApplicationMembershipRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Tenant) == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, ok, err := s.canManageTenantMembership(r.Context(), claims, body.Tenant)
	if err != nil {
		if err == core.ErrTenantNotFound {
			notFound(w, "tenant_not_found")
			return
		}
		serverErr(w, "tenant_lookup_failed")
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
// the remote_application (REFERENCE-mode write side, #75). Authorized by the
// remote_application's owner (it is the authority for its own users' restrictions).
func (s *Service) handleAttributeDefPutPOST(w http.ResponseWriter, r *http.Request) {
	_, ra, ok := s.authRemoteApplicationBySlug(w, r)
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
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
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
// mutate the remote_application with the given issuer, and returns the
// owner_user_id to persist. A global admin may manage any; otherwise the caller
// must own an EXISTING principal, or (when none exists yet) becomes its owner.
func (s *Service) canManageRemoteApplicationByIssuer(ctx context.Context, claims Claims, issuer string) (owner string, ok bool, err error) {
	uid := strings.TrimSpace(claims.UserID)
	existing, gerr := s.svc.GetRemoteApplication(ctx, issuer)
	if gerr != nil && gerr != core.ErrRemoteApplicationNotFound {
		return "", false, gerr
	}
	if claimsHasGlobalAdmin(claims) {
		if existing != nil && strings.TrimSpace(existing.OwnerUserID) != "" {
			return existing.OwnerUserID, true, nil
		}
		return uid, true, nil
	}
	if existing != nil {
		// Mutating an existing principal requires ownership.
		if !strings.EqualFold(strings.TrimSpace(existing.OwnerUserID), uid) {
			return "", false, nil
		}
		return existing.OwnerUserID, true, nil
	}
	// New principal: the registering user owns it.
	return uid, true, nil
}

// authRemoteApplicationBySlug resolves the {slug} path principal and checks the
// caller owns it (or is a global admin). It writes the error response and
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
	if !claimsHasGlobalAdmin(claims) && !strings.EqualFold(strings.TrimSpace(ra.OwnerUserID), strings.TrimSpace(claims.UserID)) {
		forbidden(w, "forbidden")
		return Claims{}, nil, false
	}
	return claims, ra, true
}

// canManageTenantMembership reports whether the caller may assign memberships on
// a tenant: a global admin, or a tenant owner. Returns the canonical slug.
func (s *Service) canManageTenantMembership(ctx context.Context, claims Claims, tenantSlug string) (canonical string, ok bool, err error) {
	if claimsHasGlobalAdmin(claims) {
		tenant, e := s.svc.ResolveTenantBySlug(ctx, tenantSlug)
		if e != nil {
			return "", false, e
		}
		return tenant.Slug, true, nil
	}
	canonical, _, isOwner, err := s.requireTenantOwner(ctx, claims.UserID, tenantSlug)
	if err != nil {
		return canonical, false, err
	}
	return canonical, isOwner, nil
}

func claimsHasGlobalAdmin(claims Claims) bool {
	for _, r := range claims.GlobalRoles {
		if strings.EqualFold(strings.TrimSpace(r), "admin") {
			return true
		}
	}
	return false
}
