package authhttp

import (
	"net/http"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
)

func (s *Service) handleTenantsListGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	mems, err := s.svc.ListUserTenantMembershipsAndRoles(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, "tenants_lookup_failed")
		return
	}
	type tenantItem struct {
		Tenant string   `json:"tenant"`
		Roles  []string `json:"roles"`
	}
	out := make([]tenantItem, 0, len(mems))
	for _, m := range mems {
		out = append(out, tenantItem{Tenant: m.Tenant, Roles: m.Roles})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": out})
}

func (s *Service) handleTenantsCreatePOST(w http.ResponseWriter, r *http.Request) {
	if s.publicTenantManagementDisabled() {
		tenantManagementDisabled(w)
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	var body struct {
		Slug string `json:"slug"`
		// Federation optionally registers a remote_application (federation
		// principal, #74) and binds it as a member of the tenant at creation: the
		// human plants the trust anchor exactly once. The block is {issuer +
		// jwks_uri} XOR {issuer + public_keys} — one trust source, never both.
		// Slug defaults to the tenant slug. Trust-config changes after creation
		// stay human-only via the remote-application routes.
		Federation *remoteApplicationRegistration `json:"federation,omitempty"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Slug) == "" {
		badRequest(w, "invalid_request")
		return
	}
	// Validate the federation block BEFORE creating anything, so an invalid
	// block rejects the whole registration (no tenant created).
	if body.Federation != nil {
		if strings.TrimSpace(body.Federation.Issuer) == "" {
			badRequest(w, "invalid_federation_issuer")
			return
		}
		if _, err := core.NormalizeRemoteAppTrustSource(body.Federation.JWKSURI, body.Federation.Mode, body.Federation.PublicKeys); err != nil {
			badRequest(w, "invalid_federation_trust_source")
			return
		}
	}
	tenant, err := s.svc.CreateTenantForUser(r.Context(), core.CreateTenantForUserRequest{
		Slug:        body.Slug,
		OwnerUserID: claims.UserID,
	})
	if err != nil {
		if err == core.ErrInvalidTenantSlug {
			badRequest(w, "invalid_tenant_slug")
			return
		}
		if err == core.ErrOwnerSlugTaken {
			badRequest(w, "owner_slug_taken")
			return
		}
		if err == core.ErrInvalidTenantOwner {
			forbidden(w, "invalid_tenant_owner")
			return
		}
		if err == core.ErrTenantLimitExceeded {
			forbidden(w, "tenant_limit_exceeded")
			return
		}
		badRequest(w, "tenant_create_failed")
		return
	}

	resp := map[string]any{"tenant": tenant.Slug}
	if body.Federation != nil {
		raSlug := strings.TrimSpace(body.Federation.Slug)
		if raSlug == "" {
			raSlug = tenant.Slug
		}
		ra, err := s.svc.UpsertRemoteApplication(r.Context(), core.RemoteApplication{
			Slug:        raSlug,
			OwnerUserID: claims.UserID,
			Issuer:      body.Federation.Issuer,
			JWKSURI:     body.Federation.JWKSURI,
			Mode:        body.Federation.Mode,
			PublicKeys:  body.Federation.PublicKeys,
			Audiences:   body.Federation.Audiences,
			Enabled:     true,
		})
		if err == nil {
			err = s.svc.AddRemoteApplicationMember(r.Context(), tenant.Slug, ra.ID, "member")
		}
		if err != nil {
			// The block was pre-validated, so this is unexpected; the tenant
			// exists but is unfederated. Surface that honestly — the caller can
			// bind via the remote-application routes (same human credential).
			s.logInternalError(r, "tenants_create", "federation_bind", "tenant_created_federation_failed", err)
			writeJSON(w, http.StatusCreated, map[string]any{
				"tenant":           tenant.Slug,
				"federation_error": "tenant_created_federation_failed",
			})
			return
		}
		if s.verifier != nil {
			_ = s.verifier.AddIssuer(ra.Issuer, nil, remoteAppOptions(*ra))
		}
		resp["federation"] = remoteApplicationView(*ra)
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Service) handleTenantsGetGET(w http.ResponseWriter, r *http.Request) {
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
	canonical, member, err := s.requireTenantMember(r.Context(), claims.UserID, tenantSlug)
	if err != nil {
		if err == core.ErrTenantNotFound {
			notFound(w, "tenant_not_found")
			return
		}
		serverErr(w, "tenant_lookup_failed")
		return
	}
	if !member {
		forbidden(w, "not_tenant_member")
		return
	}
	// Issue #58: emit a 301 redirect when the request used a historical
	// slug. requireTenantMember already resolved through `tenant_renames`
	// (which ResolveTenantBySlug consults on alias miss), so `canonical`
	// here is the live `tenants.slug`. If the inbound differs, the caller
	// dropped in a renamed-away name and gets pointed at the new path.
	if !strings.EqualFold(tenantSlug, canonical) {
		newPath := strings.Replace(r.URL.Path, tenantSlug, canonical, 1)
		if r.URL.RawQuery != "" {
			newPath += "?" + r.URL.RawQuery
		}
		w.Header().Set("Location", newPath)
		w.WriteHeader(http.StatusMovedPermanently)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenant": canonical})
}

func (s *Service) handleTenantsRenamePOST(w http.ResponseWriter, r *http.Request) {
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
	canonical, _, isOwner, err := s.requireTenantOwner(r.Context(), claims.UserID, tenantSlug)
	if err != nil {
		if err == core.ErrTenantNotFound {
			notFound(w, "tenant_not_found")
			return
		}
		serverErr(w, "tenant_lookup_failed")
		return
	}
	if !isOwner {
		forbidden(w, "forbidden")
		return
	}
	var body struct {
		NewSlug string `json:"new_slug"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.NewSlug) == "" {
		badRequest(w, "invalid_request")
		return
	}
	tenant, err := s.svc.ResolveTenantBySlug(r.Context(), canonical)
	if err != nil {
		serverErr(w, "tenant_lookup_failed")
		return
	}
	if err := s.svc.RenameTenantSlug(r.Context(), tenant.ID, body.NewSlug, claims.UserID); err != nil {
		if err == core.ErrPersonalTenantLocked {
			badRequest(w, "personal_tenant_locked")
			return
		}
		if err == core.ErrOwnerSlugTaken {
			badRequest(w, "owner_slug_taken")
			return
		}
		if err == core.ErrRenameRateLimited {
			seconds, _ := s.svc.TimeUntilTenantRenameAvailable(r.Context(), tenant.ID, time.Now())
			availability := cooldownAvailability("rename_tenant", seconds, 72*time.Hour, time.Now())
			data := availability.toMap()
			data["error"] = core.ErrCodeRenameRateLimited
			writeJSON(w, http.StatusTooManyRequests, data)
			return
		}
		badRequest(w, "tenant_rename_failed")
		return
	}
	// Return canonical slug after rename.
	renamed, err := s.svc.ResolveTenantBySlug(r.Context(), body.NewSlug)
	if err != nil {
		serverErr(w, "tenant_lookup_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenant": renamed.Slug})
}
