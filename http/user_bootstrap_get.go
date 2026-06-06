package authhttp

import (
	"net/http"
	"strings"
)

type userBootstrapResponse struct {
	UserID                string          `json:"user_id"`
	Username              string          `json:"username"`
	PersonalTenant        string          `json:"personal_org"`
	Orgs                  []orgMembership `json:"tenants"`
	UserAliases           []string        `json:"user_aliases,omitempty"`
	PersonalTenantAliases []string        `json:"personal_tenant_aliases,omitempty"`
}

func (s *Service) handleUserBootstrapGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	adminUser, err := s.svc.AdminGetUser(r.Context(), claims.UserID)
	if err != nil || adminUser == nil {
		serverErr(w, "user_lookup_failed")
		return
	}
	username := strings.TrimSpace(claims.Username)
	if adminUser.Username != nil && strings.TrimSpace(*adminUser.Username) != "" {
		username = strings.TrimSpace(*adminUser.Username)
	}
	if username == "" {
		serverErr(w, "username_missing")
		return
	}

	personalTenant, err := s.svc.GetPersonalOrgForUser(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, "personal_tenant_lookup_failed")
		return
	}
	mems, err := s.svc.ListUserTenantMembershipsAndRoles(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, "tenant_memberships_lookup_failed")
		return
	}
	tenants := make([]orgMembership, 0, len(mems))
	for _, m := range mems {
		tenants = append(tenants, orgMembership{Tenant: m.Tenant, Roles: m.Roles})
	}

	userAliases, _ := s.svc.ListUserSlugAliases(r.Context(), claims.UserID)
	personalAliases, _ := s.svc.ListOrgAliases(r.Context(), personalTenant.ID)
	writeJSON(w, http.StatusOK, userBootstrapResponse{
		UserID:                claims.UserID,
		Username:              username,
		PersonalTenant:        personalTenant.Slug,
		Orgs:                  tenants,
		UserAliases:           userAliases,
		PersonalTenantAliases: personalAliases,
	})
}
