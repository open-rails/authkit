package authhttp

import (
	"net/http"
	"strings"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/verify"

	"github.com/open-rails/authkit/embedded"
)

func (s *Service) handleUserMeGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
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
	// Preferred language is read off the user row AdminGetUser already loaded
	// (UserByID now projects preferred_language, #228) — no separate query.
	var preferredLanguage *string
	if adminUser.PreferredLanguage != nil && strings.TrimSpace(*adminUser.PreferredLanguage) != "" {
		language := *adminUser.PreferredLanguage
		preferredLanguage = &language
	}

	hasPassword, err := s.svc.HasPassword(r.Context(), adminUser.ID)
	if err != nil {
		serverErr(w, ErrDatabaseError)
		return
	}
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
	enabledProviders := s.providerNames()

	roles := adminUser.Roles
	if roles == nil {
		roles = []string{}
	}

	var createdAt *string
	if !adminUser.CreatedAt.IsZero() {
		formatted := adminUser.CreatedAt.UTC().Format(time.RFC3339)
		createdAt = &formatted
	}
	var lastAuthenticatedAt *string
	var timeUntilStepUpRequired *int64
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

	// #262: cooldown-gated action availability, so clients can ask before
	// trying. Same computation the PATCH /user/username 429 path uses; a
	// lookup failure degrades to omitting the entry rather than failing /me.
	var availability []ActionAvailability
	namingState, namingErr := s.svc.UserNamingState(r.Context(), adminUser.ID)
	if namingErr == nil {
		entry := ActionAvailability{Action: ActionUpdateUsername, Allowed: namingState.Allowed, NextAllowedAt: namingState.NextRenameAt, RetryAfterSeconds: namingState.RetryAfterSeconds}
		if !namingState.Policy.Enabled {
			entry.Reason = "renames_disabled"
		} else {
			entry.Reason = "cooldown"
		}
		seconds := int64(namingState.Policy.RenameInterval / time.Second)
		entry.CooldownSeconds = &seconds
		availability = append(availability, entry)
	}

	writeJSON(w, http.StatusOK, authkit.UserProfile{
		ID:                  adminUser.ID,
		Username:            username,
		Email:               adminUser.Email,
		PhoneNumber:         adminUser.PhoneNumber,
		EmailVerified:       adminUser.EmailVerified,
		PhoneVerified:       adminUser.PhoneVerified,
		HasPassword:         hasPassword,
		DiscordUsername:     adminUser.DiscordUsername,
		SolanaAddress:       solanaAddressPtr,
		SolanaLinkedAccount: solanaLinkedAccount,
		LinkedProviders:     linkedProviders,
		EnabledProviders:    enabledProviders,
		Roles:               roles,
		Entitlements:        adminUser.Entitlements,
		AvatarURL:           adminUser.AvatarURL,
		UserAliases:         userAliases,
		PreferredLanguage:   preferredLanguage,
		CreatedAt:           createdAt,
		Naming:              namingState,
		Availability:        availability,
		Security: authkit.UserSecurity{
			LastAuthenticatedAt:               lastAuthenticatedAt,
			TimeUntilStepUpRequired:           timeUntilStepUpRequired,
			StepUpRequiredForSensitiveActions: !verify.SensitiveClaims(claims),
			StepUpMethods:                     s.stepUpMethodsWith(hasPassword, settings, providerSlugs),
			StepUp2FA:                         s.stepUpTwoFactorOptionsWith(settings, func() string { return meEmail }),
			MFAEnabled:                        mfa.Enabled,
			MFASatisfied:                      mfa.Satisfied,
			MFAAllowedMethods:                 mfa.AllowedMethods,
		},
	})
}
