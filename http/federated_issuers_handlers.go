package authhttp

import (
	"context"
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

// federatedIssuerRegistration is the wire shape posted by a federated platform
// (the outbound client) to this resource server's accept endpoint. It is also
// the response shape returned by GET listings.
type federatedIssuerRegistration struct {
	Org      string `json:"org"`
	IssuerID string `json:"issuer_id"`
	JWKSURL  string `json:"jwks_url"`
	Status   string `json:"status,omitempty"`
}

func federatedIssuerView(fi core.FederatedOrgIssuer) federatedIssuerRegistration {
	return federatedIssuerRegistration{
		Org:      fi.OrgSlug,
		IssuerID: fi.IssuerID,
		JWKSURL:  fi.JWKSURL,
		Status:   fi.Status,
	}
}

// handleFederatedIssuerRegisterPOST is the INBOUND accept-side handler. It
// accepts + stores a federated org's issuer registration (issuer_id + jwks_url)
// so this resource server will trust delegated tokens minted by that issuer.
//
// Authorization: the caller must be owner/admin of the `org` they register the
// issuer for (RBAC owner check, same gate as other org-admin routes). This is
// the AuthKit-owned home for what tensorhub previously exposed as
// `/api/v1/platform/issuers`.
func (s *Service) handleFederatedIssuerRegisterPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	var body federatedIssuerRegistration
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, "invalid_request")
		return
	}
	orgSlug := strings.TrimSpace(body.Org)
	if orgSlug == "" {
		orgSlug = strings.TrimSpace(r.PathValue("org"))
	}
	if orgSlug == "" || strings.TrimSpace(body.IssuerID) == "" || strings.TrimSpace(body.JWKSURL) == "" {
		badRequest(w, "invalid_request")
		return
	}

	canonical, isOwner, err := s.canManageFederatedOrg(r.Context(), claims, orgSlug)
	if err != nil {
		if err == core.ErrOrgNotFound {
			notFound(w, "org_not_found")
			return
		}
		serverErr(w, "org_lookup_failed")
		return
	}
	if !isOwner {
		forbidden(w, "forbidden")
		return
	}

	fi, err := s.svc.UpsertFederatedOrgIssuer(r.Context(), core.FederatedOrgIssuer{
		OrgSlug:  canonical,
		IssuerID: body.IssuerID,
		JWKSURL:  body.JWKSURL,
		Status:   body.Status,
	})
	if err != nil {
		if err == core.ErrInvalidFederatedIssuer {
			badRequest(w, "invalid_request")
			return
		}
		serverErr(w, "federated_issuer_register_failed")
		return
	}

	// Make the newly-trusted issuer immediately usable without waiting for the
	// next store-load: register it with this service's Verifier.
	if s.verifier != nil && strings.EqualFold(fi.Status, "active") {
		_ = s.verifier.AddIssuer(fi.IssuerID, nil, IssuerOptions{JWKSURL: fi.JWKSURL, TrustedResourceAccount: fi.OrgSlug})
	}

	writeJSON(w, http.StatusOK, federatedIssuerView(*fi))
}

// handleFederatedIssuersListGET lists federated-org issuers registered with
// this resource server. Authorized for global admins (operator visibility).
func (s *Service) handleFederatedIssuersListGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	items, err := s.svc.ListFederatedOrgIssuers(r.Context(), false)
	if err != nil {
		serverErr(w, "federated_issuer_list_failed")
		return
	}
	out := make([]federatedIssuerRegistration, 0, len(items))
	for _, fi := range items {
		out = append(out, federatedIssuerView(fi))
	}
	writeJSON(w, http.StatusOK, map[string]any{"issuers": out})
}

// handleFederatedIssuerDeleteDELETE removes a federated-org issuer registration.
// Authorized by org owner/admin of the registering org.
func (s *Service) handleFederatedIssuerDeleteDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	var body federatedIssuerRegistration
	_ = decodeJSON(r, &body)
	issuerID := strings.TrimSpace(body.IssuerID)
	orgSlug := strings.TrimSpace(body.Org)
	if orgSlug == "" {
		orgSlug = strings.TrimSpace(r.PathValue("org"))
	}
	if issuerID == "" || orgSlug == "" {
		badRequest(w, "invalid_request")
		return
	}

	// Verify the issuer belongs to the named org before authz, so a caller can
	// only delete issuers for an org they own.
	existing, err := s.svc.GetFederatedOrgIssuer(r.Context(), issuerID)
	if err != nil {
		if err == core.ErrFederatedIssuerNotFound {
			notFound(w, "federated_issuer_not_found")
			return
		}
		serverErr(w, "federated_issuer_lookup_failed")
		return
	}

	canonical, isOwner, err := s.canManageFederatedOrg(r.Context(), claims, orgSlug)
	if err != nil {
		if err == core.ErrOrgNotFound {
			notFound(w, "org_not_found")
			return
		}
		serverErr(w, "org_lookup_failed")
		return
	}
	if !isOwner || !strings.EqualFold(existing.OrgSlug, canonical) {
		forbidden(w, "forbidden")
		return
	}

	if err := s.svc.DeleteFederatedOrgIssuer(r.Context(), issuerID); err != nil {
		if err == core.ErrFederatedIssuerNotFound {
			notFound(w, "federated_issuer_not_found")
			return
		}
		serverErr(w, "federated_issuer_delete_failed")
		return
	}
	if s.verifier != nil {
		s.verifier.RemoveIssuer(issuerID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// canManageFederatedOrg reports whether the authenticated caller may manage
// federated-issuer registrations for orgSlug. A global admin may manage any
// org; otherwise the caller must be an owner of the org (RBAC owner check).
func (s *Service) canManageFederatedOrg(ctx context.Context, claims Claims, orgSlug string) (canonical string, ok bool, err error) {
	if claimsHasGlobalAdmin(claims) {
		org, e := s.svc.ResolveOrgBySlug(ctx, orgSlug)
		if e != nil {
			return "", false, e
		}
		return org.Slug, true, nil
	}
	canonical, _, isOwner, err := s.requireOrgOwner(ctx, claims.UserID, orgSlug)
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
