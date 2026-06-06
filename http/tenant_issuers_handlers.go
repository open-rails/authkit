package authhttp

import (
	"context"
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

// tenantIssuerRegistration is the wire shape posted by a tenant platform
// (the outbound client) to this resource server's accept endpoint. It is also
// the response shape returned by GET listings.
type tenantIssuerRegistration struct {
	Tenant    string   `json:"tenant"`
	Issuer    string   `json:"issuer"`
	JWKSURI   string   `json:"jwks_uri"`
	Audiences []string `json:"audiences,omitempty"`
	Enabled   *bool    `json:"enabled,omitempty"`
}

type tenantIssuerResponse struct {
	Tenant    string   `json:"tenant"`
	Issuer    string   `json:"issuer"`
	JWKSURI   string   `json:"jwks_uri"`
	Audiences []string `json:"audiences"`
	Enabled   bool     `json:"enabled"`
}

func tenantIssuerView(fi core.TenantIssuer) tenantIssuerResponse {
	audiences := fi.Audiences
	if audiences == nil {
		audiences = []string{}
	}
	return tenantIssuerResponse{
		Tenant:    fi.TenantSlug,
		Issuer:    fi.Issuer,
		JWKSURI:   fi.JWKSURI,
		Audiences: audiences,
		Enabled:   fi.Enabled,
	}
}

// handleTenantIssuerRegisterPOST is the INBOUND accept-side handler. It
// accepts + stores a tenant tenant's issuer registration (issuer + jwks_uri)
// so this resource server will trust delegated tokens minted by that issuer.
//
// Authorization: the caller must be owner/admin of the `tenant` they register the
// issuer for (RBAC owner check, same gate as other tenant-admin routes). This is
// the AuthKit-owned home for what tensorhub previously exposed as
// `/api/v1/platform/issuers`.
func (s *Service) handleTenantIssuerRegisterPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	var body tenantIssuerRegistration
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, "invalid_request")
		return
	}
	tenantSlug := strings.TrimSpace(body.Tenant)
	if tenantSlug == "" {
		tenantSlug = strings.TrimSpace(r.PathValue("tenant"))
	}
	if tenantSlug == "" || strings.TrimSpace(body.Issuer) == "" || strings.TrimSpace(body.JWKSURI) == "" {
		badRequest(w, "invalid_request")
		return
	}

	canonical, isOwner, err := s.canManageTenantIssuer(r.Context(), claims, tenantSlug)
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

	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	fi, err := s.svc.UpsertTenantIssuer(r.Context(), core.TenantIssuer{
		TenantSlug: canonical,
		Issuer:     body.Issuer,
		JWKSURI:    body.JWKSURI,
		Audiences:  body.Audiences,
		Enabled:    enabled,
	})
	if err != nil {
		if err == core.ErrInvalidTenantIssuer {
			badRequest(w, "invalid_request")
			return
		}
		serverErr(w, "tenant_issuer_register_failed")
		return
	}

	// Make the newly-trusted issuer immediately usable without waiting for the
	// next store-load: register it with this service's Verifier.
	if s.verifier != nil && fi.Enabled {
		_ = s.verifier.AddIssuer(fi.Issuer, nil, IssuerOptions{JWKSURI: fi.JWKSURI, TrustedResourceAccount: fi.TenantSlug})
	}

	writeJSON(w, http.StatusOK, tenantIssuerView(*fi))
}

// handleTenantIssuersListGET lists tenant-tenant issuers registered with
// this resource server. Authorized for global admins (operator visibility).
func (s *Service) handleTenantIssuersListGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	items, err := s.svc.ListTenantIssuers(r.Context(), false)
	if err != nil {
		serverErr(w, "tenant_issuer_list_failed")
		return
	}
	out := make([]tenantIssuerResponse, 0, len(items))
	for _, fi := range items {
		out = append(out, tenantIssuerView(fi))
	}
	writeJSON(w, http.StatusOK, map[string]any{"issuers": out})
}

// handleTenantIssuerDeleteDELETE removes a tenant-tenant issuer registration.
// Authorized by tenant owner/admin of the registering tenant.
func (s *Service) handleTenantIssuerDeleteDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	var body tenantIssuerRegistration
	_ = decodeJSON(r, &body)
	issuerID := strings.TrimSpace(body.Issuer)
	tenantSlug := strings.TrimSpace(body.Tenant)
	if tenantSlug == "" {
		tenantSlug = strings.TrimSpace(r.PathValue("tenant"))
	}
	if issuerID == "" || tenantSlug == "" {
		badRequest(w, "invalid_request")
		return
	}

	// Verify the issuer belongs to the named tenant before authz, so a caller can
	// only delete issuers for an tenant they own.
	existing, err := s.svc.GetTenantIssuer(r.Context(), issuerID)
	if err != nil {
		if err == core.ErrTenantIssuerNotFound {
			notFound(w, "tenant_issuer_not_found")
			return
		}
		serverErr(w, "tenant_issuer_lookup_failed")
		return
	}

	canonical, isOwner, err := s.canManageTenantIssuer(r.Context(), claims, tenantSlug)
	if err != nil {
		if err == core.ErrTenantNotFound {
			notFound(w, "tenant_not_found")
			return
		}
		serverErr(w, "tenant_lookup_failed")
		return
	}
	if !isOwner || !strings.EqualFold(existing.TenantSlug, canonical) {
		forbidden(w, "forbidden")
		return
	}

	if err := s.svc.DeleteTenantIssuer(r.Context(), issuerID); err != nil {
		if err == core.ErrTenantIssuerNotFound {
			notFound(w, "tenant_issuer_not_found")
			return
		}
		serverErr(w, "tenant_issuer_delete_failed")
		return
	}
	if s.verifier != nil {
		s.verifier.RemoveIssuer(issuerID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// canManageTenantIssuer reports whether the authenticated caller may manage
// tenant-issuer registrations for tenantSlug. A global admin may manage any
// tenant; otherwise the caller must be an owner of the tenant (RBAC owner check).
func (s *Service) canManageTenantIssuer(ctx context.Context, claims Claims, tenantSlug string) (canonical string, ok bool, err error) {
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
