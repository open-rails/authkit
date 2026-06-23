package authhttp

import (
	"net/http"
	"strings"
	"time"

	"github.com/open-rails/authkit/core"
	"github.com/open-rails/authkit/internal/db"
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
	Entitlements                      []string                  `json:"entitlements"`
	Biography                         *string                   `json:"biography,omitempty"`
	UserAliases                       []string                  `json:"user_aliases,omitempty"`
	PreferredLanguage                 *string                   `json:"preferred_language,omitempty"`
	CreatedAt                         *string                   `json:"created_at,omitempty"`
	LastAuthenticatedAt               *string                   `json:"last_authenticated_at,omitempty"`
	TimeUntilReauthRequired           *int64                    `json:"time_until_reauth_required,omitempty"`
	ReauthRequiredForSensitiveActions *bool                     `json:"reauth_required_for_sensitive_actions,omitempty"`
	Mandatory2FARequired              bool                      `json:"mandatory_2fa_required"`
	Mandatory2FASatisfied             bool                      `json:"mandatory_2fa_satisfied"`
	Mandatory2FAAllowedMethods        []string                  `json:"mandatory_2fa_allowed_methods,omitempty"`
}

func (s *Service) handleUserMeGET(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLUserMe) {
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}

	adminUser, err := s.svc.AdminGetUser(r.Context(), claims.UserID)
	if err != nil || adminUser == nil {
		serverErr(w, ErrUserLookupFailed)
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
		serverErr(w, ErrUsernameMissing)
		return
	}
	var preferredLanguage *string
	if preferred, err := s.svc.GetPreferredLanguage(r.Context(), adminUser.ID); err == nil {
		if strings.TrimSpace(preferred.Language) != "" {
			language := preferred.Language
			preferredLanguage = &language
		}
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
	userAliases := []string{}
	if pg := s.svc.Postgres(); pg != nil {
		queries := db.New(db.ForSchema(pg, s.svc.Schema()))
		if providers, err := queries.UserProviderSlugs(r.Context(), adminUser.ID); err == nil {
			for _, provider := range providers {
				provider = strings.TrimSpace(provider)
				if provider != "" {
					linkedProviders = append(linkedProviders, provider)
				}
			}
		}
		if aliases, err := queries.UserSlugAliases(r.Context(), adminUser.ID); err == nil {
			for _, alias := range aliases {
				alias = strings.TrimSpace(alias)
				if alias != "" {
					userAliases = append(userAliases, alias)
				}
			}
		}
	}
	enabledProviders := []string{}
	for provider := range s.authProviders() {
		enabledProviders = append(enabledProviders, provider)
	}

	// Return the user's roles.
	var rolesPtr *[]string
	roles := adminUser.Roles
	if roles == nil {
		roles = []string{}
	}
	rolesPtr = &roles

	var createdAt *string
	if !adminUser.CreatedAt.IsZero() {
		formatted := adminUser.CreatedAt.UTC().Format(time.RFC3339)
		createdAt = &formatted
	}
	var lastAuthenticatedAt *string
	var timeUntilReauthRequired *int64
	var reauthRequiredForSensitiveActions *bool
	if !claims.AuthTime.IsZero() {
		formatted := claims.AuthTime.UTC().Format(time.RFC3339)
		lastAuthenticatedAt = &formatted
		remaining := core.SensitiveActionFreshAuthWindow - time.Since(claims.AuthTime)
		if remaining < 0 {
			remaining = 0
		}
		seconds := int64((remaining + time.Second - time.Nanosecond) / time.Second)
		timeUntilReauthRequired = &seconds
	}
	required := !SensitiveClaims(claims)
	reauthRequiredForSensitiveActions = &required
	mandatory2FA, err := s.svc.Mandatory2FAStatus(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, ErrDatabaseError)
		return
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
		Entitlements:                      adminUser.Entitlements,
		Biography:                         adminUser.Biography,
		UserAliases:                       userAliases,
		PreferredLanguage:                 preferredLanguage,
		CreatedAt:                         createdAt,
		LastAuthenticatedAt:               lastAuthenticatedAt,
		TimeUntilReauthRequired:           timeUntilReauthRequired,
		ReauthRequiredForSensitiveActions: reauthRequiredForSensitiveActions,
		Mandatory2FARequired:              mandatory2FA.Required,
		Mandatory2FASatisfied:             mandatory2FA.Satisfied,
		Mandatory2FAAllowedMethods:        mandatory2FA.AllowedMethods,
	}
	writeJSON(w, http.StatusOK, resp)
}
