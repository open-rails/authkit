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
		serverErr(w, "orgs_lookup_failed")
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
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Slug) == "" {
		badRequest(w, "invalid_request")
		return
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

	writeJSON(w, http.StatusCreated, map[string]any{"tenant": tenant.Slug})
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
			availability := cooldownAvailability("rename_org", seconds, 72*time.Hour, time.Now())
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
