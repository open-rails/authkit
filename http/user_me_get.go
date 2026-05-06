package authhttp

import (
	"net/http"
	"strings"
	"time"
)

type userMeResponse struct {
	ID               string           `json:"id"`
	Email            *string          `json:"email"`
	PhoneNumber      *string          `json:"phone_number"`
	Username         string           `json:"username"`
	DiscordUsername  *string          `json:"discord_username,omitempty"`
	SolanaAddress    *string          `json:"solana_address,omitempty"`
	LinkedProviders  []string         `json:"linked_providers,omitempty"`
	EnabledProviders []string         `json:"enabled_providers,omitempty"`
	EmailVerified    bool             `json:"email_verified"`
	PhoneVerified    bool             `json:"phone_verified"`
	HasPassword      bool             `json:"has_password"`
	Roles            *[]string        `json:"roles,omitempty"`
	Orgs             *[]orgMembership `json:"orgs,omitempty"`
	Entitlements     []string         `json:"entitlements"`
	Biography        *string          `json:"biography,omitempty"`
	CreatedAt        *string          `json:"created_at,omitempty"`
}

type orgMembership struct {
	Org   string   `json:"org"`
	Roles []string `json:"roles"`
}

func (s *Service) handleUserMeGET(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLUserMe) {
		tooMany(w)
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, "unauthorized")
		return
	}

	adminUser, err := s.svc.AdminGetUser(r.Context(), claims.UserID)
	if err != nil || adminUser == nil {
		serverErr(w, "user_lookup_failed")
		return
	}

	username := ""
	if adminUser.Username != nil {
		username = strings.TrimSpace(*adminUser.Username)
	}
	if username == "" {
		username = strings.TrimSpace(claims.Username)
	}
	if username == "" {
		serverErr(w, "username_missing")
		return
	}

	hasPassword := s.svc.HasPassword(r.Context(), adminUser.ID)
	solanaAddress, _ := s.svc.GetSolanaAddress(r.Context(), adminUser.ID)
	var solanaAddressPtr *string
	if solanaAddress != "" {
		solanaAddressPtr = &solanaAddress
	}
	// TODO - Move to service layer. This is currently the only place we need to know about linked providers, but if we add more endpoints that surface this info, it may make sense to return it from the service directly instead of doing a separate DB query here.
	linkedProviders := []string{}
	if pg := s.svc.Postgres(); pg != nil {
		rows, err := pg.Query(r.Context(), `
			SELECT provider_slug
			FROM profiles.user_providers
			WHERE user_id = $1 AND provider_slug IS NOT NULL
		`, adminUser.ID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var provider string
				if err := rows.Scan(&provider); err == nil {
					provider = strings.TrimSpace(provider)
					if provider != "" {
						linkedProviders = append(linkedProviders, provider)
					}
				}
			}
		}
	}
	enabledProviders := []string{}
	if s.oidcProviders != nil {
		for provider := range s.oidcProviders {
			enabledProviders = append(enabledProviders, provider)
		}
	}

	var rolesPtr *[]string
	var orgsPtr *[]orgMembership
	if strings.EqualFold(strings.TrimSpace(s.svc.Options().OrgMode), "single") {
		roles := adminUser.Roles
		if roles == nil {
			roles = []string{}
		}
		rolesPtr = &roles
	} else if strings.EqualFold(strings.TrimSpace(s.svc.Options().OrgMode), "multi") {
		// Multi-mode: return memberships + org-scoped roles from server-side DB.
		mems, mErr := s.svc.ListUserOrgMembershipsAndRoles(r.Context(), adminUser.ID)
		if mErr != nil {
			serverErr(w, "org_memberships_lookup_failed")
			return
		}
		orgs := make([]orgMembership, 0, len(mems))
		for _, m := range mems {
			orgs = append(orgs, orgMembership{Org: m.Org, Roles: m.Roles})
		}
		orgsPtr = &orgs
	}

	var createdAt *string
	if !adminUser.CreatedAt.IsZero() {
		formatted := adminUser.CreatedAt.UTC().Format(time.RFC3339)
		createdAt = &formatted
	}

	resp := userMeResponse{
		ID:               adminUser.ID,
		Email:            adminUser.Email,
		PhoneNumber:      adminUser.PhoneNumber,
		Username:         username,
		DiscordUsername:  adminUser.DiscordUsername,
		SolanaAddress:    solanaAddressPtr,
		LinkedProviders:  linkedProviders,
		EnabledProviders: enabledProviders,
		EmailVerified:    adminUser.EmailVerified,
		PhoneVerified:    adminUser.PhoneVerified,
		HasPassword:      hasPassword,
		Roles:            rolesPtr,
		Orgs:             orgsPtr,
		Entitlements:     adminUser.Entitlements,
		Biography:        adminUser.Biography,
		CreatedAt:        createdAt,
	}
	writeJSON(w, http.StatusOK, resp)
}
