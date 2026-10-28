package httpapi

import (
	"net/http"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
)

// The tenant directory: root:tenants:read and root:tenants:manage, checked at
// the route. Selecting a tenant for the request does not change the target.

var tenantNotFound = map[error]errmodel.Code{iam.ErrTenantNotFound: errmodel.CodeNotFound, iam.ErrTenantRequired: errmodel.CodeNotFound}

func (s *Service) handleAdminTenantCreatePOST(w http.ResponseWriter, r *http.Request) {
	var req TenantCreateRequest
	if err := decodeJSON(r, &req); err != nil || req.ID.IsZero() {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if err := s.svc.CreateTenant(r.Context(), iam.Tenant{ID: req.ID, Slug: req.Slug}); err != nil {
		writeError(w, err)
		return
	}
	tenant, err := s.svc.Tenant(r.Context(), req.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, tenant)
}

func (s *Service) handleAdminTenantGET(w http.ResponseWriter, r *http.Request) {
	id, err := iam.ParseTenantID(r.PathValue("tenant_id"))
	if err != nil {
		fail(w, errmodel.CodeNotFound)
		return
	}
	tenant, err := s.svc.Tenant(r.Context(), id)
	if err != nil {
		writeError(w, remap(err, tenantNotFound))
		return
	}
	writeJSON(w, http.StatusOK, tenant)
}

func (s *Service) handleAdminTenantPATCH(w http.ResponseWriter, r *http.Request) {
	id, err := iam.ParseTenantID(r.PathValue("tenant_id"))
	if err != nil {
		fail(w, errmodel.CodeNotFound)
		return
	}
	var req TenantRenameRequest
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	tenant, err := s.svc.RenameTenant(r.Context(), id, req.Slug)
	if err != nil {
		writeError(w, remap(err, tenantNotFound))
		return
	}
	writeJSON(w, http.StatusOK, tenant)
}

func (s *Service) handleAdminTenantBySlugGET(w http.ResponseWriter, r *http.Request) {
	tenant, err := s.svc.ResolveTenant(r.Context(), r.PathValue("slug"))
	if err != nil {
		writeError(w, remap(err, tenantNotFound))
		return
	}
	writeJSON(w, http.StatusOK, tenant)
}
