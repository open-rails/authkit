package embedded

import (
	"context"
	authkit "github.com/open-rails/authkit"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestUserProfileProjection_DB(t *testing.T) {
	ctx := context.Background()
	svc, _ := newHardeningService(t)
	u, email := newHardeningUser(t, ctx, svc, "profile")
	require.NoError(t, svc.AdminSetPassword(ctx, u.ID, "Correct-horse-battery-1"))
	require.NoError(t, svc.MarkEmailVerified(ctx, u.ID))
	_, err := svc.Enable2FA(ctx, u.ID, "email", nil, AllowAdditionalFactors)
	require.NoError(t, err)
	require.NoError(t, svc.LinkProviderByIssuer(ctx, u.ID, "https://github.com", "github", "profile-"+u.ID, nil))

	authTime := time.Now().Add(-time.Minute)
	profile, err := svc.UserProfile(ctx, ProfileInput{
		UserID: u.ID, ClaimsUsername: "ignored", AuthTime: authTime, StepUpSatisfied: true,
		EnabledProviders:       []string{"github", "google"},
		ProviderSupportsStepUp: func(p string) bool { return p == "github" },
	})
	require.NoError(t, err)
	require.Equal(t, u.ID, profile.ID)
	require.Equal(t, *u.Username, profile.Username, "the row's username wins over the claim")
	require.Equal(t, email, *profile.Email)
	require.True(t, profile.EmailVerified)
	require.True(t, profile.HasPassword)
	require.Equal(t, []string{"github"}, profile.LinkedProviders)
	require.Equal(t, []string{"github", "google"}, profile.EnabledProviders)
	require.Equal(t, []string{"password", "2fa", "github"}, profile.Security.StepUpMethods)
	require.True(t, profile.Security.MFAEnabled)
	require.False(t, profile.Security.StepUpRequiredForSensitiveActions)
	require.NotNil(t, profile.Security.LastAuthenticatedAt)
	require.NotNil(t, profile.Security.StepUp2FA)
	require.Equal(t, "email", profile.Security.StepUp2FA.DefaultMethod)
	require.Equal(t, MaskDestination(email), profile.Security.StepUp2FA.Options[0].VerificationID)
	require.Len(t, profile.Availability, 1)
	require.Equal(t, authkit.ActionUpdateUsername, profile.Availability[0].Action)

	_, err = svc.UserProfile(ctx, ProfileInput{UserID: "00000000-0000-7000-8000-000000000000"})
	require.ErrorContains(t, err, "load_user: ")
}
