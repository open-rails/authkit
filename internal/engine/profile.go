package engine

// The caller's own profile (GET /me) as ONE engine projection (ak#318): one
// user-row read and one 2FA-settings read threaded through identity, contact
// state, linked providers, naming state and the security/step-up view.

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
	u, err := s.getUserByID(ctx, in.UserID)
	if err != nil || u == nil {
		return authflow.UserProfile{}, stageErr("load_user", errOrUnauthorized(err))
	}
	roles := []string{}
	if held, err := s.rootRoles(ctx, []string{u.ID}); err == nil && !held[u.ID].IsZero() {
		roles = append(roles, held[u.ID].String())
	}
	user := publicUser(u, time.Now())
	if user.Username == "" {
		user.Username = strings.TrimSpace(in.ClaimsUsername)
	}
	hasPassword, err := s.HasPassword(ctx, u.ID)
	if err != nil {
		return authflow.UserProfile{}, stageErr("load_password", err)
	}
	solanaLinkedAccount, _ := s.getSolanaLinkedAccount(ctx, u.ID)
	linkedProviders := []string{}
	providerSlugs, err := s.ProviderSlugs(ctx, u.ID)
	if err == nil {
		for _, provider := range providerSlugs {
			if provider = strings.TrimSpace(provider); provider != "" {
				linkedProviders = append(linkedProviders, provider)
			}
		}
	}
	var lastAuthenticatedAt *time.Time
	var timeUntilStepUpRequired *int64
	if !in.AuthTime.IsZero() {
		at := in.AuthTime
		lastAuthenticatedAt = &at
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
	mfa, err := s.mfaStatusWith(settings, settingsErr)
	if err != nil {
		return authflow.UserProfile{}, stageErr("load_2fa", err)
	}
	// A naming lookup failure leaves the zero state rather than failing the
	// profile.
	namingState, _ := s.UserNamingState(ctx, u.ID)
	return authflow.UserProfile{
		User:                user,
		HasPassword:         hasPassword,
		SolanaLinkedAccount: solanaLinkedAccount,
		LinkedProviders:     linkedProviders,
		Roles:               roles,
		Entitlements:        s.listEntitlements(ctx, u.ID),
		Naming:              namingState,
		Security: authflow.UserSecurity{
			LastAuthenticatedAt:               lastAuthenticatedAt,
			TimeUntilStepUpRequired:           timeUntilStepUpRequired,
			StepUpRequiredForSensitiveActions: !in.StepUpSatisfied,
			StepUpMethods:                     authflow.StepUpMethods(hasPassword, settings, providerSlugs, in.ProviderSupportsStepUp),
			StepUp2FA:                         authflow.NewStepUpTwoFactorOptions(settings),
			MFAEnabled:                        mfa.Enabled,
			MFASatisfied:                      mfa.Satisfied,
			MFAAllowedMethods:                 mfa.AllowedMethods,
		},
	}, nil
}
