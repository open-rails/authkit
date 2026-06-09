package authhttp

import (
	"net/http"
	"strings"
	"time"

	"github.com/open-rails/authkit/core"
)

type userMeResponse struct {
	ID                                string                    `json:"id"`
	Email                             *string                   `json:"email"`
	PhoneNumber                       *string                   `json:"phone_number"`
	Username                          string                    `json:"username"`
	DiscordUsername                   *string                   `json:"discord_username,omitempty"`
	SolanaAddress                     *string                   `json:"solana_address,omitempty"`
	SolanaLinkedAccount               *core.SolanaLinkedAccount `json:"solana_linked_account,omitempty"`
	LinkedProviders                   []string                  `json:"linked_providers,omitempty"`
	EnabledProviders                  []string                  `json:"enabled_providers,omitempty"`
	EmailVerified                     bool                      `json:"email_verified"`
	PhoneVerified                     bool                      `json:"phone_verified"`
	HasPassword                       bool                      `json:"has_password"`
	Roles                             *[]string                 `json:"roles,omitempty"`
	Tenants                           *[]tenantMembership       `json:"tenants,omitempty"`
	Entitlements                      []string                  `json:"entitlements"`
	Biography                         *string                   `json:"biography,omitempty"`
	PreferredLocale                   *string                   `json:"preferred_locale,omitempty"`
	PreferredLocaleSource             *string                   `json:"preferred_locale_source,omitempty"`
	PreferredLocaleUpdatedAt          *string                   `json:"preferred_locale_updated_at,omitempty"`
	CreatedAt                         *string                   `json:"created_at,omitempty"`
	LastAuthenticatedAt               *string                   `json:"last_authenticated_at,omitempty"`
	TimeUntilReauthRequired           *int64                    `json:"time_until_reauth_required,omitempty"`
	ReauthRequiredForSensitiveActions *bool                     `json:"reauth_required_for_sensitive_actions,omitempty"`
}

type tenantMembership struct {
	Tenant string   `json:"tenant"`
	Roles  []string `json:"roles"`
}

func (s *Service) handleUserMeGET(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLUserMe) {
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
	var preferredLocale *string
	var preferredLocaleSource *string
	var preferredLocaleUpdatedAt *string
	if preferred, err := s.svc.GetPreferredLocale(r.Context(), adminUser.ID); err == nil {
		if strings.TrimSpace(preferred.Locale) != "" {
			locale := preferred.Locale
			preferredLocale = &locale
		}
		if strings.TrimSpace(preferred.Source) != "" {
			source := preferred.Source
			preferredLocaleSource = &source
		}
		preferredLocaleUpdatedAt = formatOptionalTime(preferred.UpdatedAt)
	}

	hasPassword := s.svc.HasPassword(r.Context(), adminUser.ID)
	solanaLinkedAccount, _ := s.svc.GetSolanaLinkedAccount(r.Context(), adminUser.ID)
	solanaAddress := ""
	if solanaLinkedAccount != nil {
		solanaAddress = solanaLinkedAccount.Address
	} else {
		solanaAddress, _ = s.svc.GetSolanaAddress(r.Context(), adminUser.ID)
	}
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
	for provider := range s.authProviders() {
		enabledProviders = append(enabledProviders, provider)
	}

	// (issue 60) Always return the user's global roles AND their tenant memberships
	// (memberships may be empty for tenant-free users). No tenant-mode branch.
	var rolesPtr *[]string
	var tenantsPtr *[]tenantMembership
	roles := adminUser.Roles
	if roles == nil {
		roles = []string{}
	}
	rolesPtr = &roles
	mems, mErr := s.svc.ListUserTenantMembershipsAndRoles(r.Context(), adminUser.ID)
	if mErr != nil {
		serverErr(w, "tenant_memberships_lookup_failed")
		return
	}
	tenants := make([]tenantMembership, 0, len(mems))
	for _, m := range mems {
		tenants = append(tenants, tenantMembership{Tenant: m.Tenant, Roles: m.Roles})
	}
	tenantsPtr = &tenants

	var createdAt *string
	if !adminUser.CreatedAt.IsZero() {
		formatted := adminUser.CreatedAt.UTC().Format(time.RFC3339)
		createdAt = &formatted
	}
	var lastAuthenticatedAt *string
	var timeUntilReauthRequired *int64
	var reauthRequiredForSensitiveActions *bool
	if strings.TrimSpace(claims.SessionID) != "" {
		if freshness, err := s.svc.SessionFreshness(r.Context(), claims.UserID, claims.SessionID, time.Now()); err == nil {
			formatted := freshness.LastAuthenticatedAt.UTC().Format(time.RFC3339)
			lastAuthenticatedAt = &formatted
			seconds := int64((freshness.TimeUntilReauthRequired + time.Second - time.Nanosecond) / time.Second)
			timeUntilReauthRequired = &seconds
			required := freshness.ReauthRequiredForSensitiveOps
			reauthRequiredForSensitiveActions = &required
		}
	}

	resp := userMeResponse{
		ID:                                adminUser.ID,
		Email:                             adminUser.Email,
		PhoneNumber:                       adminUser.PhoneNumber,
		Username:                          username,
		DiscordUsername:                   adminUser.DiscordUsername,
		SolanaAddress:                     solanaAddressPtr,
		SolanaLinkedAccount:               solanaLinkedAccount,
		LinkedProviders:                   linkedProviders,
		EnabledProviders:                  enabledProviders,
		EmailVerified:                     adminUser.EmailVerified,
		PhoneVerified:                     adminUser.PhoneVerified,
		HasPassword:                       hasPassword,
		Roles:                             rolesPtr,
		Tenants:                           tenantsPtr,
		Entitlements:                      adminUser.Entitlements,
		Biography:                         adminUser.Biography,
		PreferredLocale:                   preferredLocale,
		PreferredLocaleSource:             preferredLocaleSource,
		PreferredLocaleUpdatedAt:          preferredLocaleUpdatedAt,
		CreatedAt:                         createdAt,
		LastAuthenticatedAt:               lastAuthenticatedAt,
		TimeUntilReauthRequired:           timeUntilReauthRequired,
		ReauthRequiredForSensitiveActions: reauthRequiredForSensitiveActions,
	}
	writeJSON(w, http.StatusOK, resp)
}
