package authprovider

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// AK security audit F4: the GitHub provider must not assume an email is verified.
// GitHub's /user.email is a public profile field with no verification guarantee;
// a verified address is sourced only from the /user/emails fallback, whose
// primary+verified selection lives in the http callback wiring.

func TestGitHubProvider_PrimaryEmailNotAssumedVerified(t *testing.T) {
	p, ok := BuiltIn("github")
	require.True(t, ok)
	require.NotNil(t, p.IdentityMapper)

	// A typical /user response: carries an email but NO verification signal.
	id, err := p.IdentityMapper(map[string]any{
		"id":    float64(123),
		"email": "user@example.com",
		"login": "octocat",
		"name":  "Octo Cat",
	})
	require.NoError(t, err)
	require.Equal(t, "user@example.com", id.Email)
	require.False(t, id.EmailVerified, "GitHub /user.email must NOT be assumed verified (AK F4)")
}

func TestGitHubProvider_UsesEmailFallbackEndpoint(t *testing.T) {
	p, ok := BuiltIn("github")
	require.True(t, ok)
	// The verified-email source is the /user/emails fallback endpoint.
	require.Equal(t, "https://api.github.com/user/emails", p.EmailFallbackURL)
	require.Equal(t, "application/vnd.github+json", p.EmailFallbackAccept)
}
