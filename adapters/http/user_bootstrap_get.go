package authhttp

import (
	"net/http"
	"strings"
)

type userBootstrapResponse struct {
	UserID             string          `json:"user_id"`
	Username           string          `json:"username"`
	PersonalOrg        string          `json:"personal_org"`
	Orgs               []orgMembership `json:"orgs"`
	UserAliases        []string        `json:"user_aliases,omitempty"`
	PersonalOrgAliases []string        `json:"personal_org_aliases,omitempty"`
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

	personalOrg, err := s.svc.GetPersonalOrgForUser(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, "personal_org_lookup_failed")
		return
	}
	mems, err := s.svc.ListUserOrgMembershipsAndRoles(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, "org_memberships_lookup_failed")
		return
	}
	orgs := make([]orgMembership, 0, len(mems))
	for _, m := range mems {
		orgs = append(orgs, orgMembership{Org: m.Org, Roles: m.Roles})
	}

	userAliases, _ := s.svc.ListUserSlugAliases(r.Context(), claims.UserID)
	personalAliases, _ := s.svc.ListOrgAliases(r.Context(), personalOrg.ID)
	writeJSON(w, http.StatusOK, userBootstrapResponse{
		UserID:             claims.UserID,
		Username:           username,
		PersonalOrg:        personalOrg.Slug,
		Orgs:               orgs,
		UserAliases:        userAliases,
		PersonalOrgAliases: personalAliases,
	})
}
