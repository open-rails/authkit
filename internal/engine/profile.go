package engine

// The caller's own profile (GET /me) as ONE engine projection (ak#318): one
// user-row read and one 2FA-settings read threaded through identity, contact
// state, linked providers, naming state and the security/step-up view.

import (
	"context"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
)

// UserProfile builds the caller's profile. Errors: the user row is missing
// (stage "load_user"), or a store failure (stage "load_password",
// "load_providers").
func (s *Engine) UserProfile(ctx context.Context, in authflow.ProfileInput) (authflow.UserProfile, error) {
	u, err := s.getUserByID(ctx, in.UserID)
	if err != nil || u == nil {
		return authflow.UserProfile{}, stageErr("load_user", errOrUnauthorized(err))
	}
	var rootRole *iam.Role
	if held, err := s.rootRoles(ctx, []string{u.ID}); err == nil && !held[u.ID].IsZero() {
		role := held[u.ID]
		rootRole = &role
	}
	user := publicUser(u, time.Now())
	if user.Username == "" {
		user.Username = strings.TrimSpace(in.ClaimsUsername)
	}
	hasPassword, err := s.HasPassword(ctx, u.ID)
	if err != nil {
		return authflow.UserProfile{}, stageErr("load_password", err)
	}
	solanaWallet, _ := s.getSolanaLinkedAccount(ctx, u.ID)
	links, err := s.q.UserProvidersLinked(ctx, u.ID)
	if err != nil {
		return authflow.UserProfile{}, stageErr("load_providers", err)
	}
	providers := make([]authflow.LinkedProvider, 0, len(links))
	for _, link := range links {
		providers = append(providers, authflow.LinkedProvider{Provider: link.ProviderSlug, Email: link.EmailAtProvider, LinkedAt: link.CreatedAt})
	}
	// A naming lookup failure leaves the zero state rather than failing the
	// profile.
	namingState, _ := s.UserNamingState(ctx, u.ID)
	return authflow.UserProfile{
		User:         user,
		RootRole:     rootRole,
		Entitlements: s.listEntitlements(ctx, u.ID),
		HasPassword:  hasPassword,
		Providers:    providers,
		SolanaWallet: solanaWallet,
		Naming:       namingState,
	}, nil
}

// UserSecurity builds the caller's security view: the presented token's
// freshness, the step-up methods and the MFA state, from one 2FA-settings
// read.
func (s *Engine) UserSecurity(ctx context.Context, in authflow.ProfileInput) (authflow.UserSecurity, error) {
	hasPassword, err := s.HasPassword(ctx, in.UserID)
	if err != nil {
		return authflow.UserSecurity{}, stageErr("load_password", err)
	}
	providerSlugs, _ := s.ProviderSlugs(ctx, in.UserID)
	fresh := authflow.FreshAuth{StepUpRequiredForSensitiveActions: !in.StepUpSatisfied, AuthMethods: in.AuthMethods}
	if !in.AuthTime.IsZero() {
		at := in.AuthTime
		fresh.LastAuthenticatedAt = &at
		remaining := max(authflow.SensitiveActionFreshAuthWindow-time.Since(in.AuthTime), 0)
		fresh.StepUpRequiredInSeconds = int64((remaining + time.Second - time.Nanosecond) / time.Second)
	}
	if fresh.AuthMethods == nil {
		fresh.AuthMethods = []string{}
	}
	settings, settingsErr := s.Get2FASettings(ctx, in.UserID)
	mfa, err := s.mfaStatusWith(settings, settingsErr)
	if err != nil {
		return authflow.UserSecurity{}, stageErr("load_2fa", err)
	}
	return authflow.UserSecurity{
		FreshAuth:         fresh,
		StepUpMethods:     authflow.StepUpMethods(hasPassword, settings, providerSlugs, in.ProviderSupportsStepUp),
		StepUp2FA:         authflow.NewStepUpTwoFactorOptions(settings),
		MFAEnabled:        mfa.Enabled,
		MFASatisfied:      mfa.Satisfied,
		MFAAllowedMethods: mfa.AllowedMethods,
	}, nil
}
