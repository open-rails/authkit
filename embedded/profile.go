package embedded

// The caller's own profile (GET /me) as ONE engine projection (ak#318): one
// user-row read and one 2FA-settings read threaded through identity, contact
// state, linked providers, naming state, cooldown availability and the
// security/step-up view.

import (
	"context"
	"sort"
	"strings"
	"time"

	authkit "github.com/open-rails/authkit"
)

// ProfileInput is what the transport knows that the engine does not: the
// verified claims' username/auth-time/sensitivity and the deployment's
// provider registry.
type ProfileInput struct {
	UserID          string
	ClaimsUsername  string // fallback when the row carries no username
	AuthTime        time.Time
	StepUpSatisfied bool // the presented token is fresh enough for sensitive actions
	// EnabledProviders lists the deployment's login providers;
	// ProviderSupportsStepUp reports which linked providers can re-authenticate.
	EnabledProviders       []string
	ProviderSupportsStepUp func(provider string) bool
}

// UserProfile builds the caller's profile. Errors: the user row is missing
// (stage "load_user"), or a store failure (stage "load_password" /
// "load_2fa").
func (s *Client) UserProfile(ctx context.Context, in ProfileInput) (authkit.UserProfile, error) {
	u, err := s.AdminGetUser(ctx, in.UserID)
	if err != nil || u == nil {
		return authkit.UserProfile{}, stageErr("load_user", errOrUnauthorized(err))
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
		return authkit.UserProfile{}, stageErr("load_password", err)
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
		remaining := SensitiveActionFreshAuthWindow - time.Since(in.AuthTime)
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
		return authkit.UserProfile{}, stageErr("load_2fa", err)
	}
	email := ""
	if u.Email != nil {
		email = *u.Email
	}
	// Cooldown-gated action availability (#262): a lookup failure omits the
	// entry rather than failing the profile.
	var availability []authkit.ActionAvailability
	namingState, namingErr := s.UserNamingState(ctx, u.ID)
	if namingErr == nil {
		entry := authkit.ActionAvailability{Action: authkit.ActionUpdateUsername, Allowed: namingState.Allowed, NextAllowedAt: namingState.NextRenameAt, RetryAfterSeconds: namingState.RetryAfterSeconds}
		if !namingState.Policy.Enabled {
			entry.Reason = "renames_disabled"
		} else {
			entry.Reason = "cooldown"
		}
		seconds := int64(namingState.Policy.RenameInterval / time.Second)
		entry.CooldownSeconds = &seconds
		availability = append(availability, entry)
	}
	return authkit.UserProfile{
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
		Security: authkit.UserSecurity{
			LastAuthenticatedAt:               lastAuthenticatedAt,
			TimeUntilStepUpRequired:           timeUntilStepUpRequired,
			StepUpRequiredForSensitiveActions: !in.StepUpSatisfied,
			StepUpMethods:                     StepUpMethods(hasPassword, settings, providerSlugs, in.ProviderSupportsStepUp),
			StepUp2FA:                         StepUpTwoFactorOptions(settings, email),
			MFAEnabled:                        mfa.Enabled,
			MFASatisfied:                      mfa.Satisfied,
			MFAAllowedMethods:                 mfa.AllowedMethods,
		},
	}, nil
}

// StepUpMethods lists how the user can re-authenticate for a sensitive
// action: password, an enabled second factor, and every linked provider that
// supports step-up (de-duplicated, sorted). Pure over already-loaded inputs.
func StepUpMethods(hasPassword bool, settings *TwoFactorSettings, providerSlugs []string, supportsStepUp func(string) bool) []string {
	methods := []string{}
	if hasPassword {
		methods = append(methods, "password")
	}
	if settings != nil && settings.Enabled {
		methods = append(methods, "2fa")
	}
	seen := make(map[string]struct{}, len(providerSlugs))
	distinct := make([]string, 0, len(providerSlugs))
	for _, provider := range providerSlugs {
		if _, dup := seen[provider]; dup {
			continue
		}
		seen[provider] = struct{}{}
		distinct = append(distinct, provider)
	}
	sort.Strings(distinct)
	for _, provider := range distinct {
		if supportsStepUp != nil && supportsStepUp(provider) {
			methods = append(methods, provider)
		}
	}
	return methods
}

// StepUpTwoFactorOptions lists the second factors a step-up can use, with the
// code destination masked. Nil when 2FA is not enabled.
func StepUpTwoFactorOptions(settings *TwoFactorSettings, emailDestination string) *authkit.StepUpTwoFactorOptions {
	if settings == nil || !settings.Enabled {
		return nil
	}
	factors := settings.Factors
	if len(factors) == 0 && strings.TrimSpace(settings.Method) != "" {
		factors = []TwoFactorFactor{{Method: strings.TrimSpace(settings.Method), PhoneNumber: settings.PhoneNumber, IsDefault: true, Enabled: true}}
	}
	if len(factors) == 0 {
		return nil
	}
	out := &authkit.StepUpTwoFactorOptions{}
	for _, factor := range factors {
		method := strings.ToLower(strings.TrimSpace(factor.Method))
		if !factor.Enabled || !ValidTwoFactorStepUpMethod(method) {
			continue
		}
		option := authkit.StepUpTwoFactorOption{Method: method, IsDefault: factor.IsDefault}
		switch method {
		case "email":
			if emailDestination != "" {
				option.VerificationID = MaskDestination(emailDestination)
			}
		case "sms":
			if factor.PhoneNumber != nil {
				option.VerificationID = MaskDestination(*factor.PhoneNumber)
			}
		}
		out.Methods = append(out.Methods, method)
		out.Options = append(out.Options, option)
		if factor.IsDefault {
			out.DefaultMethod = method
		}
	}
	if len(out.Methods) == 0 {
		return nil
	}
	if out.DefaultMethod == "" {
		out.DefaultMethod = out.Methods[0]
		out.Options[0].IsDefault = true
	}
	return out
}

// ValidTwoFactorStepUpMethod reports whether method can satisfy a step-up.
func ValidTwoFactorStepUpMethod(method string) bool {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "email", "sms", "totp":
		return true
	default:
		return false
	}
}

// MaskDestination hides all but the last five characters of a code
// destination (email or phone) for display as a verification id.
func MaskDestination(value string) string {
	if len(value) <= 5 {
		return value
	}
	return strings.Repeat("*", len(value)-5) + value[len(value)-5:]
}
