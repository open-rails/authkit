package authhttp

import (
	"net/http"
	"strings"
	"time"

	"github.com/open-rails/authkit/embedded"
)

type userMeResponse struct {
	ID                                string                          `json:"id"`
	Email                             *string                         `json:"email"`
	PhoneNumber                       *string                         `json:"phone_number"`
	Username                          string                          `json:"username"`
	DiscordUsername                   *string                         `json:"discord_username,omitempty"`
	SolanaAddress                     *string                         `json:"solana_address,omitempty"`
	SolanaLinkedAccount               *embedded.SolanaLinkedAccount   `json:"solana_linked_account,omitempty"`
	LinkedProviders                   []string                        `json:"linked_providers,omitempty"`
	EnabledProviders                  []string                        `json:"enabled_providers,omitempty"`
	EmailVerified                     bool                            `json:"email_verified"`
	PhoneVerified                     bool                            `json:"phone_verified"`
	HasPassword                       bool                            `json:"has_password"`
	Roles                             *[]string                       `json:"roles,omitempty"`
	Entitlements                      []string                        `json:"entitlements"`
	Biography                         *string                         `json:"biography,omitempty"`
	UserAliases                       []string                        `json:"user_aliases,omitempty"`
	PreferredLanguage                 *string                         `json:"preferred_language,omitempty"`
	CreatedAt                         *string                         `json:"created_at,omitempty"`
	LastAuthenticatedAt               *string                         `json:"last_authenticated_at,omitempty"`
	TimeUntilStepUpRequired           *int64                          `json:"time_until_step_up_required,omitempty"`
	StepUpRequiredForSensitiveActions *bool                           `json:"step_up_required_for_sensitive_actions,omitempty"`
	StepUpMethods                     []string                        `json:"step_up_methods,omitempty"`
	StepUp2FA                         *stepUpTwoFactorOptionsResponse `json:"step_up_2fa,omitempty"`
	MFAEnabled                        bool                            `json:"mfa_enabled"`
	MFASatisfied                      bool                            `json:"mfa_satisfied"`
	MFAAllowedMethods                 []string                        `json:"mfa_allowed_methods,omitempty"`
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
	// Preferred language is read off the user row AdminGetUser already loaded
	// (UserByID now projects preferred_language, #228) — no separate query.
	var preferredLanguage *string
	if adminUser.PreferredLanguage != nil && strings.TrimSpace(*adminUser.PreferredLanguage) != "" {
		language := *adminUser.PreferredLanguage
		preferredLanguage = &language
	}

	hasPassword := s.svc.HasPassword(r.Context(), adminUser.ID)
	solanaLinkedAccount, slErr := s.svc.GetSolanaLinkedAccount(r.Context(), adminUser.ID)
	solanaAddress := ""
	if solanaLinkedAccount != nil {
		solanaAddress = solanaLinkedAccount.Address
	} else if slErr != nil {
		// Only fall back to the address-only lookup when the linked-account read
		// ERRORED; a clean "no wallet" already means there is no address to find,
		// so this avoids a second user_providers query for every non-Solana user.
		solanaAddress, _ = s.svc.GetSolanaAddress(r.Context(), adminUser.ID)
	}
	var solanaAddressPtr *string
	if solanaAddress != "" {
		solanaAddressPtr = &solanaAddress
	}
	linkedProviders := []string{}
	userAliases := []string{}
	// providerSlugs is the raw provider-slug list; reused below for the step-up
	// methods so /me does not issue a second UserProviderSlugsDistinct read (#228).
	var providerSlugs []string
	if providers, aliases, err := s.svc.UserProfileLinks(r.Context(), adminUser.ID); err == nil {
		providerSlugs = providers
		for _, provider := range providers {
			provider = strings.TrimSpace(provider)
			if provider != "" {
				linkedProviders = append(linkedProviders, provider)
			}
		}
		for _, alias := range aliases {
			alias = strings.TrimSpace(alias)
			if alias != "" {
				userAliases = append(userAliases, alias)
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
	var timeUntilStepUpRequired *int64
	var stepUpRequiredForSensitiveActions *bool
	if !claims.AuthTime.IsZero() {
		formatted := claims.AuthTime.UTC().Format(time.RFC3339)
		lastAuthenticatedAt = &formatted
		remaining := embedded.SensitiveActionFreshAuthWindow - time.Since(claims.AuthTime)
		if remaining < 0 {
			remaining = 0
		}
		seconds := int64((remaining + time.Second - time.Nanosecond) / time.Second)
		timeUntilStepUpRequired = &seconds
	}
	required := !SensitiveClaims(claims)
	stepUpRequiredForSensitiveActions = &required
	// Read the user's 2FA settings ONCE and thread the result through MFA status,
	// the step-up methods, and the step-up 2FA options (#228) — the three used to
	// each re-run Get2FASettings independently.
	settings, settingsErr := s.svc.Get2FASettings(r.Context(), adminUser.ID)
	mfa, err := s.svc.MFAStatusWith(settings, settingsErr)
	if err != nil {
		serverErr(w, ErrDatabaseError)
		return
	}
	meEmail := ""
	if adminUser.Email != nil {
		meEmail = *adminUser.Email
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
		TimeUntilStepUpRequired:           timeUntilStepUpRequired,
		StepUpRequiredForSensitiveActions: stepUpRequiredForSensitiveActions,
		StepUpMethods:                     s.stepUpMethodsWith(hasPassword, settings, providerSlugs),
		StepUp2FA:                         s.stepUpTwoFactorOptionsWith(settings, func() string { return meEmail }),
		MFAEnabled:                        mfa.Enabled,
		MFASatisfied:                      mfa.Satisfied,
		MFAAllowedMethods:                 mfa.AllowedMethods,
	}
	writeJSON(w, http.StatusOK, resp)
}
