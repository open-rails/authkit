package engine

// The caller's own profile (GET /me) as ONE engine projection (ak#318): one
// user-row read and one 2FA-settings read threaded through identity, contact
// state, linked providers, naming state, cooldown availability and the
// security/step-up view.

import (
	"context"
	"strings"
	"time"

	"github.com/open-rails/authkit/internal/authflow"
)

// UserProfile builds the caller's profile. Errors: the user row is missing
// (stage "load_user"), or a store failure (stage "load_password" /
// "load_2fa").
func (s *Engine) UserProfile(ctx context.Context, in authflow.ProfileInput) (authflow.UserProfile, error) {
	u, err := s.AdminGetUser(ctx, in.UserID)
	if err != nil || u == nil {
		return authflow.UserProfile{}, stageErr("load_user", errOrUnauthorized(err))
	}
	username := ""
	if u.Username != nil {
		username = strings.TrimSpace(*u.Username)
	}
	if username == "" {
		username = strings.TrimSpace(in.ClaimsUsername)
	}
	var preferredLanguage *string
	if u.PreferredLanguage != nil && strings.TrimSpace(*u.PreferredLanguage) != "" {
		language := *u.PreferredLanguage
		preferredLanguage = &language
	}
	hasPassword, err := s.HasPassword(ctx, u.ID)
	if err != nil {
		return authflow.UserProfile{}, stageErr("load_password", err)
	}
	solanaLinkedAccount, slErr := s.GetSolanaLinkedAccount(ctx, u.ID)
	solanaAddress := ""
	if solanaLinkedAccount != nil {
		solanaAddress = solanaLinkedAccount.Address
	} else if slErr != nil {
		// Only when the linked-account read ERRORED; a clean "no wallet" already
		// means there is no address to find.
		solanaAddress, _ = s.GetSolanaAddress(ctx, u.ID)
	}
	var solanaAddressPtr *string
	if solanaAddress != "" {
		solanaAddressPtr = &solanaAddress
	}
	linkedProviders := []string{}
	userAliases := []string{}
	var providerSlugs []string
	if providers, aliases, err := s.UserProfileLinks(ctx, u.ID); err == nil {
		providerSlugs = providers
		for _, provider := range providers {
			if provider = strings.TrimSpace(provider); provider != "" {
				linkedProviders = append(linkedProviders, provider)
			}
		}
		for _, alias := range aliases {
			if alias = strings.TrimSpace(alias); alias != "" {
				userAliases = append(userAliases, alias)
			}
		}
	}
	roles := u.Roles
	if roles == nil {
		roles = []string{}
	}
	var createdAt *string
	if !u.CreatedAt.IsZero() {
		formatted := u.CreatedAt.UTC().Format(time.RFC3339)
		createdAt = &formatted
	}
	var lastAuthenticatedAt *string
	var timeUntilStepUpRequired *int64
	if !in.AuthTime.IsZero() {
		formatted := in.AuthTime.UTC().Format(time.RFC3339)
		lastAuthenticatedAt = &formatted
		remaining := authflow.SensitiveActionFreshAuthWindow - time.Since(in.AuthTime)
		if remaining < 0 {
			remaining = 0
		}
		seconds := int64((remaining + time.Second - time.Nanosecond) / time.Second)
		timeUntilStepUpRequired = &seconds
	}
	// One 2FA-settings read feeds MFA status, the step-up methods and the
	// step-up 2FA options.
	settings, settingsErr := s.Get2FASettings(ctx, u.ID)
	mfa, err := s.MFAStatusWith(settings, settingsErr)
	if err != nil {
		return authflow.UserProfile{}, stageErr("load_2fa", err)
	}
	email := ""
	if u.Email != nil {
		email = *u.Email
	}
	// Cooldown-gated action availability (#262): a lookup failure omits the
	// entry rather than failing the profile.
	var availability []authflow.ActionAvailability
	namingState, namingErr := s.UserNamingState(ctx, u.ID)
	if namingErr == nil {
		entry := authflow.ActionAvailability{Action: authflow.ActionUpdateUsername, Allowed: namingState.Allowed, NextAllowedAt: namingState.NextRenameAt, RetryAfterSeconds: namingState.RetryAfterSeconds}
		if !namingState.Policy.Enabled {
			entry.Reason = "renames_disabled"
		} else {
			entry.Reason = "cooldown"
		}
		seconds := int64(s.NamingPolicy().RenameInterval / time.Second)
		entry.CooldownSeconds = &seconds
		availability = append(availability, entry)
	}
	return authflow.UserProfile{
		ID:                  u.ID,
		Username:            username,
		Email:               u.Email,
		PhoneNumber:         u.PhoneNumber,
		EmailVerified:       u.EmailVerified,
		PhoneVerified:       u.PhoneVerified,
		HasPassword:         hasPassword,
		DiscordUsername:     u.DiscordUsername,
		SolanaAddress:       solanaAddressPtr,
		SolanaLinkedAccount: solanaLinkedAccount,
		LinkedProviders:     linkedProviders,
		EnabledProviders:    in.EnabledProviders,
		Roles:               roles,
		Entitlements:        u.Entitlements,
		AvatarURL:           u.AvatarURL,
		UserAliases:         userAliases,
		PreferredLanguage:   preferredLanguage,
		CreatedAt:           createdAt,
		Naming:              namingState,
		Availability:        availability,
		Security: authflow.UserSecurity{
			LastAuthenticatedAt:               lastAuthenticatedAt,
			TimeUntilStepUpRequired:           timeUntilStepUpRequired,
			StepUpRequiredForSensitiveActions: !in.StepUpSatisfied,
			StepUpMethods:                     authflow.StepUpMethods(hasPassword, settings, providerSlugs, in.ProviderSupportsStepUp),
			StepUp2FA:                         authflow.NewStepUpTwoFactorOptions(settings, email),
			MFAEnabled:                        mfa.Enabled,
			MFASatisfied:                      mfa.Satisfied,
			MFAAllowedMethods:                 mfa.AllowedMethods,
		},
	}, nil
}
